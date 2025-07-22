import os
import json
from datetime import datetime
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.secret_key = app.config['SECRET_KEY']

# File paths for user data
USERS_FILE = 'users.json'
PENDING_FILE = 'pending_users.json'
DECLINED_FILE = 'declined_users.json'

def load_json(file_path):
    try:
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump([], f)
            return []
        
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_json(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

# Database setup
def get_db_connection():
    conn = sqlite3.connect('school.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                last_login TEXT
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                date_posted TEXT NOT NULL,
                is_pinned INTEGER DEFAULT 0
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                filename TEXT NOT NULL,
                upload_date TEXT NOT NULL
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS syllabus (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                class_name TEXT NOT NULL,
                year TEXT NOT NULL,
                month TEXT NOT NULL,
                exam_name TEXT NOT NULL,
                subject TEXT NOT NULL,
                filename TEXT NOT NULL,
                upload_date TEXT NOT NULL
            )
        ''')
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                date TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                admin_notes TEXT
            )
        ''')
        
        # Create default admin if not exists
        admin = conn.execute('SELECT * FROM admin WHERE username = ?', ('admin',)).fetchone()
        if not admin:
            conn.execute(
                'INSERT INTO admin (username, password) VALUES (?, ?)',
                ('admin', generate_password_hash('admin123'))
            )
            conn.commit()
        conn.close()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Auth decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in as admin to access this page', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

# Syllabus page
@app.route('/syllabus')
def syllabus():
    return render_template('syllabus.html')

# Notifications page
@app.route('/notifications')
def notifications():
    return render_template('notifications.html')

# Documents page
@app.route('/documents')
def documents():
    return render_template('documents.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check declined users first
        declined_users = load_json(DECLINED_FILE)
        declined = next((u for u in declined_users if u['username'] == username), None)
        if declined:
            flash(f'Your account was declined. Reason: {declined.get("reason", "No reason provided")}', 'danger')
            return redirect(url_for('login'))
        
        # Check approved users
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['username'] == username), None)
        
        if user and user['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user.get('role', 'student')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            username = request.form.get('username')
            password = request.form.get('password')
            class_name = request.form.get('class')
            roll_number = request.form.get('roll_number')
            
            if not all([first_name, last_name, username, password, class_name, roll_number]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('signup'))
            
            # Check if username exists in any files
            all_users = load_json(USERS_FILE) + load_json(PENDING_FILE) + load_json(DECLINED_FILE)
            if any(u['username'] == username for u in all_users):
                flash('Username already exists', 'danger')
                return redirect(url_for('signup'))
            
            new_user = {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'password': password,
                'class': class_name,
                'roll_number': roll_number,
                'status': 'pending',
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Save to pending users
            pending_users = load_json(PENDING_FILE)
            pending_users.append(new_user)
            save_json(pending_users, PENDING_FILE)
            
            flash('Your application has been submitted for admin approval', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during signup: {e}")
            flash('An error occurred during registration', 'danger')
    
    return render_template('signup.html')

@app.route('/contact-admin', methods=['GET', 'POST'])
def contact_admin():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if not all([name, email, subject, message]):
            flash('Please fill all required fields', 'danger')
            return redirect(url_for('contact_admin'))
        
        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO feedback (name, email, subject, message, date) VALUES (?, ?, ?, ?, ?)',
                (name, email, subject, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            conn.close()
            
            flash('Your message has been sent to admin!', 'success')
            return redirect(url_for('contact_admin'))
        except Exception as e:
            print(f"Error saving contact message: {e}")
            flash('Failed to send your message', 'danger')
    
    return render_template('contact_admin.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    conn = get_db_connection()
    try:
        pinned_notices = conn.execute('SELECT * FROM notifications WHERE is_pinned = 1 ORDER BY date_posted DESC LIMIT 2').fetchall()
        recent_syllabus = conn.execute('SELECT * FROM syllabus ORDER BY upload_date DESC LIMIT 2').fetchall()
        return render_template('index.html', pinned_notices=pinned_notices, recent_syllabus=recent_syllabus)
    finally:
        conn.close()

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admin WHERE username = ?', (username,)).fetchone()
        
        if admin and check_password_hash(admin['password'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            conn.execute(
                'UPDATE admin SET last_login = ? WHERE username = ?',
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            conn.close()
            
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    try:
        # Get counts for dashboard
        notifications_count = conn.execute('SELECT COUNT(*) FROM notifications').fetchone()[0]
        syllabus_count = conn.execute('SELECT COUNT(*) FROM syllabus').fetchone()[0]
        documents_count = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
        feedbacks_count = conn.execute('SELECT COUNT(*) FROM feedback').fetchone()[0]
        
        # Get recent feedbacks
        feedbacks = conn.execute('SELECT * FROM feedback ORDER BY date DESC LIMIT 5').fetchall()
        
        # Get pending users count
        pending_users = load_json(PENDING_FILE)
        pending_approvals = len(pending_users)
        
        # Get system stats
        approved_users = len(load_json(USERS_FILE))
        declined_users = len(load_json(DECLINED_FILE))
        
        return render_template('admin/dashboard.html',
                           notifications_count=notifications_count,
                           syllabus_count=syllabus_count,
                           documents_count=documents_count,
                           feedbacks_count=feedbacks_count,
                           feedbacks=feedbacks,
                           pending_approvals=pending_approvals,
                           approved_users=approved_users,
                           declined_users=declined_users)
    finally:
        conn.close()

@app.route('/admin/pending-users')
@admin_required
def pending_users():
    pending_users = load_json(PENDING_FILE)
    return render_template('admin/pending_users.html', users=pending_users)

@app.route('/admin/approve-user/<username>')
@admin_required
def approve_user(username):
    try:
        pending_users = load_json(PENDING_FILE)
        user = next((u for u in pending_users if u['username'] == username), None)
        
        if user:
            # Remove from pending
            pending_users = [u for u in pending_users if u['username'] != username]
            save_json(pending_users, PENDING_FILE)
            
            # Add to approved users
            approved_users = load_json(USERS_FILE)
            approved_users.append(user)
            save_json(approved_users, USERS_FILE)
            
            flash(f'User {username} approved successfully', 'success')
        else:
            flash('User not found in pending list', 'danger')
    except Exception as e:
        print(f"Error approving user: {e}")
        flash('Failed to approve user', 'danger')
    
    return redirect(url_for('pending_users'))

@app.route('/admin/decline-user/<username>', methods=['GET', 'POST'])
@admin_required
def decline_user(username):
    if request.method == 'POST':
        reason = request.form.get('reason', 'No reason provided')
        try:
            pending_users = load_json(PENDING_FILE)
            user = next((u for u in pending_users if u['username'] == username), None)
            
            if user:
                # Remove from pending
                pending_users = [u for u in pending_users if u['username'] != username]
                save_json(pending_users, PENDING_FILE)
                
                # Add to declined with reason
                user['reason'] = reason
                declined_users = load_json(DECLINED_FILE)
                declined_users.append(user)
                save_json(declined_users, DECLINED_FILE)
                
                flash(f'User {username} declined with reason: {reason}', 'success')
            else:
                flash('User not found in pending list', 'danger')
        except Exception as e:
            print(f"Error declining user: {e}")
            flash('Failed to decline user', 'danger')
        
        return redirect(url_for('pending_users'))
    
    return render_template('admin/decline_user.html', username=username)

@app.route('/admin/feedback/<int:id>/resolve', methods=['POST'])
@admin_required
def resolve_feedback(id):
    try:
        notes = request.form.get('notes', '')
        conn = get_db_connection()
        conn.execute(
            'UPDATE feedback SET status = ?, admin_notes = ? WHERE id = ?',
            ('resolved', notes, id)
        )
        conn.commit()
        conn.close()
        flash('Feedback marked as resolved', 'success')
    except Exception as e:
        print(f"Error resolving feedback: {e}")
        flash('Failed to resolve feedback', 'danger')
    
    return redirect(url_for('admin_dashboard'))

# [Include all other existing routes for documents, syllabus, notifications, etc.]

if __name__ == '__main__':
    # Create required files if they don't exist
    for file in [USERS_FILE, PENDING_FILE, DECLINED_FILE]:
        if not os.path.exists(file):
            save_json([], file)
    
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    app.run(host="0.0.0.0", port=5000, debug=True)
