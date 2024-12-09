from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(basedir, 'lost_found.db'),
    SECRET_KEY='your_secret_key',
    UPLOAD_FOLDER=os.path.join(basedir, 'static', 'uploads'),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    items = db.relationship('Item', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)  # 'lost', 'found', 'recovered'
    image_path = db.Column(db.String(200))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_info = db.Column(db.String(200))
    reward = db.Column(db.String(100))
    claims = db.relationship('Claim', backref='item', lazy=True)
    recovered_date = db.Column(db.DateTime)

class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    claimer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_claimed = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(500))
    status = db.Column(db.String(20), default='pending')

@login_manager.user_loader
def load_user(id):
    try:
        return User.query.get(int(id))
    except:
        return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    recent_lost = Item.query.filter_by(status='lost').order_by(Item.date_reported.desc()).limit(5).all()
    recent_found = Item.query.filter_by(status='found').order_by(Item.date_reported.desc()).limit(5).all()
    return render_template('index.html', recent_lost=recent_lost, recent_found=recent_found)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            if User.query.filter_by(username=request.form['username']).first():
                flash('Username already exists', 'error')
                return redirect(url_for('register'))

            user = User(
                username=request.form['username'],
                email=request.form['email']
            )
            user.set_password(request.form['password'])
            db.session.add(user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            user = User.query.filter_by(username=request.form['username']).first()
            if user and user.check_password(request.form['password']):
                login_user(user)
                return redirect(url_for('index'))
            flash('Invalid username or password', 'error')
        except Exception as e:
            flash('Login failed. Please try again.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/report/<type>', methods=['GET', 'POST'])
@login_required
def report(type):
    if type not in ['lost', 'found']:
        flash('Invalid report type', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            image_path = None
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_path = f'uploads/{filename}'

            new_item = Item(
                description=request.form['description'],
                location=request.form['location'],
                status=type,
                image_path=image_path,
                owner_id=current_user.id,
                contact_info=request.form.get('contact_info', ''),
                reward=request.form.get('reward', '')
            )

            db.session.add(new_item)
            db.session.commit()
            flash(f'{type.capitalize()} item reported successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error reporting item. Please try again.', 'error')

    return render_template('report.html', type=type)

@app.route('/items/<status>')
def view_items(status):
    if status not in ['lost', 'found']:
        flash('Invalid status', 'error')
        return redirect(url_for('index'))

    items = Item.query.filter_by(status=status).order_by(Item.date_reported.desc()).all()
    return render_template('items.html', items=items, status=status)


@app.route('/item/<int:item_id>')
def view_item(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item_detail.html', item=item)

@app.route('/item/<int:item_id>/recover', methods=['POST'])
@login_required
def recover_item(item_id):
    item = Item.query.get_or_404(item_id)

    if item.owner_id != current_user.id:
        flash('You are not authorized to recover this item', 'error')
        return redirect(url_for('view_item', item_id=item_id))

    try:
        item.status = 'recovered'
        item.recovered_date = datetime.utcnow()
        db.session.commit()
        flash('Item marked as recovered successfully!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        flash('Error recovering item. Please try again.', 'error')
        return redirect(url_for('view_item', item_id=item_id))

@app.context_processor
def utility_processor():
    def time_ago(date):
        now = datetime.utcnow()
        diff = now - date
        if diff.days > 365:
            return f"{diff.days // 365} years ago"
        if diff.days > 30:
            return f"{diff.days // 30} months ago"
        if diff.days > 0:
            return f"{diff.days} days ago"
        if diff.seconds > 3600:
            return f"{diff.seconds // 3600} hours ago"
        if diff.seconds > 60:
            return f"{diff.seconds // 60} minutes ago"
        return "just now"
    return dict(time_ago=time_ago)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Advanced application context
def init_db():
    with app.app_context():
        db.create_all()  # Creates all database tables if they don't exist.

if __name__ == '__main__':
    init_db()  # Initialize the database and create tables
    app.run(debug=True)
