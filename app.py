from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
from flask import jsonify
from datetime import datetime
import sqlite3
from functools import wraps

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.secret_key = app.config['SECRET_KEY']

import time
from datetime import datetime, timedelta
import json

# Add these with your other configuration variables
MAX_LOGIN_ATTEMPTS = 4
BLOCK_TIME_HOURS = 24
FAILED_ATTEMPTS_FILE = 'failed_attempts.json'

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr

        # ✅ 1. Check if user/IP is blocked
        if is_blocked(username, ip_address):
            flash('Too many failed attempts. Please try again after 24 hours.', 'danger')
            return redirect(url_for('login'))

        # ✅ 2. Check if user is in declined_users.json
        declined_users = load_json('declined_users.json')
        declined_user = next((u for u in declined_users if u['username'] == username), None)
        if declined_user:
            reason = declined_user.get('reason', 'No reason provided')
            flash(f'You are Declined. Reason: {reason}', 'danger')
            return redirect(url_for('login'))

        # ✅ 3. Validate against regular users
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['username'] == username), None)

        if user and user['password'] == password:
            # ✅ Successful login - reset attempts
            attempts_data = load_failed_attempts()
            if username in attempts_data:
                attempts_data[username]['attempts'] = 0
            if ip_address in attempts_data:
                attempts_data[ip_address]['attempts'] = 0
            save_failed_attempts(attempts_data)

            session['logged_in'] = True
            session['username'] = username
            session['role'] = user.get('role', 'student')
            return redirect(url_for('home'))
        else:
            # ❌ Failed login - record attempt
            record_failed_attempt(username, ip_address)
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

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if not all([name, email, subject, message]):
            flash('Please fill all required fields', 'danger')
            return redirect(url_for('contact'))
        
        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO feedback (name, email, subject, message, date) VALUES (?, ?, ?, ?, ?)',
                (name, email, subject, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            conn.close()
            
            flash('Your message has been sent successfully!', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            print(f"Error processing contact form: {e}")
            flash('An error occurred while sending your message', 'danger')
    return render_template('contact.html')

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

@app.route('/documents')
@login_required
def documents():
    conn = get_db_connection()
    try:
        documents = conn.execute('SELECT * FROM documents ORDER BY upload_date DESC').fetchall()
        return render_template('documents.html', documents=documents)
    finally:
        conn.close()

@app.route('/syllabus')
@login_required
def syllabus():
    conn = get_db_connection()
    try:
        syllabus = conn.execute('''
            SELECT * FROM syllabus 
            ORDER BY year DESC, class_name ASC, subject ASC
        ''').fetchall()
        return render_template('syllabus.html', syllabus=syllabus)
    finally:
        conn.close()

@app.route('/notifications')
@login_required
def notifications():
    conn = get_db_connection()
    try:
        notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC').fetchall()
        return render_template('notifications.html', notifications=notifications)
    finally:
        conn.close()

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        
        # Check if admin/IP is blocked
        if is_blocked(username, ip_address):
            flash('Too many failed attempts. Please try again after 24 hours.', 'danger')
            return redirect(url_for('admin_login'))
        
        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admin WHERE username = ?', (username,)).fetchone()
        
        if admin and check_password_hash(admin['password'], password):
            # Successful login - reset attempts if any
            attempts_data = load_failed_attempts()
            if username in attempts_data:
                attempts_data[username]['attempts'] = 0
                save_failed_attempts(attempts_data)
            if ip_address in attempts_data:
                attempts_data[ip_address]['attempts'] = 0
                save_failed_attempts(attempts_data)
            
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
            # Failed login - record attempt
            record_failed_attempt(username, ip_address)
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

@app.route('/admin/approved-users')
@admin_required
def approved_users():
    # Load users from users.json
    with open('users.json') as f:
        users = json.load(f)
    
    # Filter approved users (assuming status field exists)
    approved_users = [user for user in users if user.get('status') == 'approved']
    
    return render_template('admin/approved_users.html', users=approved_users)

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
            ('resolved', notes, id))
        conn.commit()
        conn.close()
        flash('Feedback marked as resolved', 'success')
    except Exception as e:
        print(f"Error resolving feedback: {e}")
        flash('Failed to resolve feedback', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/notifications', methods=['GET', 'POST'])
@admin_required
def admin_notifications():
    conn = get_db_connection()
    try:
        if request.method == 'POST':
            title = request.form.get('title')
            content = request.form.get('content')
            is_pinned = 1 if request.form.get('is_pinned') else 0
            date_posted = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            conn.execute(
                'INSERT INTO notifications (title, content, date_posted, is_pinned) VALUES (?, ?, ?, ?)',
                (title, content, date_posted, is_pinned))
            conn.commit()
            flash('Notification added successfully!', 'success')
        
        notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC').fetchall()
        return render_template('admin/notifications.html', notifications=notifications)
    finally:
        conn.close()

@app.route('/admin/delete_notification/<int:id>')
@admin_required
def delete_notification(id):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM notifications WHERE id = ?', (id,))
        conn.commit()
        flash('Notification deleted successfully!', 'success')
    finally:
        conn.close()
    return redirect(url_for('admin_notifications'))

@app.route('/admin/toggle-pin/<int:id>')
@admin_required
def toggle_pin_notification(id):
    conn = get_db_connection()
    try:
        notification = conn.execute('SELECT * FROM notifications WHERE id = ?', (id,)).fetchone()
        if notification:
            new_status = 0 if notification['is_pinned'] else 1
            conn.execute('UPDATE notifications SET is_pinned = ? WHERE id = ?', (new_status, id))
            conn.commit()
            flash('Notification pin status updated', 'success')
        else:
            flash('Notification not found', 'danger')
    except Exception as e:
        print(f"Error toggling pin status: {e}")
        flash('Failed to update pin status', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_notifications'))

@app.route('/admin/upload_syllabus', methods=['GET', 'POST'])
@admin_required
def upload_syllabus():
    if request.method == 'POST':
        try:
            required_fields = ['class_name', 'year', 'month', 'exam_name', 'subject']
            if not all(request.form.get(field) for field in required_fields) or not request.files.get('file'):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('upload_syllabus'))
            
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                upload_folder = app.config['UPLOAD_FOLDER']
                
                os.makedirs(upload_folder, exist_ok=True)
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)
                
                conn = get_db_connection()
                conn.execute(
                    '''INSERT INTO syllabus 
                    (class_name, year, month, exam_name, subject, filename, upload_date) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (
                        request.form['class_name'],
                        request.form['year'],
                        request.form['month'],
                        request.form['exam_name'],
                        request.form['subject'],
                        filename,
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    )
                )
                conn.commit()
                conn.close()
                
                flash('Syllabus uploaded successfully!', 'success')
                return redirect(url_for('syllabus'))
            else:
                flash('Invalid file type. Allowed formats: PDF, DOC, DOCX', 'danger')
        except Exception as e:
            print(f"Error uploading syllabus: {str(e)}")
            flash('An error occurred while uploading syllabus', 'danger')
    
    return render_template('admin/upload_syllabus.html')

@app.route('/admin/delete_syllabus/<int:id>', methods=['POST'])
@admin_required
def delete_syllabus(id):
    try:
        conn = get_db_connection()
        syllabus = conn.execute('SELECT filename FROM syllabus WHERE id = ?', (id,)).fetchone()
        if not syllabus:
            flash('Syllabus not found', 'danger')
            return redirect(url_for('syllabus'))
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], syllabus['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        conn.execute('DELETE FROM syllabus WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        
        flash('Syllabus deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting syllabus: {e}")
        flash('An error occurred while deleting syllabus', 'danger')
    
    return redirect(url_for('syllabus'))

@app.route('/admin/upload_document', methods=['GET', 'POST'])
@admin_required
def upload_document():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            name = request.form.get('name')
            category = request.form.get('category')
            
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO documents (name, category, filename, upload_date) VALUES (?, ?, ?, ?)',
                (name, category, filename, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            conn.close()
            
            flash('Document uploaded successfully', 'success')
            return redirect(url_for('documents'))
        else:
            flash('Allowed file types are txt, pdf, png, jpg, jpeg, gif', 'danger')
    
    return render_template('admin/upload_document.html')

@app.route('/admin/delete_document/<int:id>', methods=['POST'])
@admin_required
def delete_document(id):
    try:
        conn = get_db_connection()
        document = conn.execute('SELECT filename FROM documents WHERE id = ?', (id,)).fetchone()
        if not document:
            flash('Document not found', 'danger')
            return redirect(url_for('documents'))
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        conn.execute('DELETE FROM documents WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        
        flash('Document deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting document: {e}")
        flash('An error occurred while deleting document', 'danger')
    
    return redirect(url_for('documents'))

@app.route('/admin/change_password', methods=['GET', 'POST'])
@admin_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            flash('Please fill all fields', 'danger')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        
        conn = get_db_connection()
        try:
            admin = conn.execute('SELECT * FROM admin WHERE username = ?', (session['admin_username'],)).fetchone()
            
            if not check_password_hash(admin['password'], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('change_password'))
            
            conn.execute(
                'UPDATE admin SET password = ? WHERE username = ?',
                (generate_password_hash(new_password), session['admin_username']))
            conn.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        finally:
            conn.close()
    
    return render_template('admin/change_password.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

# Static file serving
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def load_failed_attempts():
    try:
        with open(FAILED_ATTEMPTS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_failed_attempts(data):
    with open(FAILED_ATTEMPTS_FILE, 'w') as f:
        json.dump(data, f)

def is_blocked(username, ip_address):
    attempts_data = load_failed_attempts()
    now = datetime.now()
    
    # Check by username
    if username in attempts_data:
        last_attempt = datetime.fromisoformat(attempts_data[username]['timestamp'])
        if attempts_data[username]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            if now - last_attempt < timedelta(hours=BLOCK_TIME_HOURS):
                return True
            else:
                # Block period expired, reset attempts
                attempts_data[username]['attempts'] = 0
                save_failed_attempts(attempts_data)
    
    # Check by IP address
    if ip_address in attempts_data:
        last_attempt = datetime.fromisoformat(attempts_data[ip_address]['timestamp'])
        if attempts_data[ip_address]['attempts'] >= MAX_LOGIN_ATTEMPTS:
            if now - last_attempt < timedelta(hours=BLOCK_TIME_HOURS):
                return True
            else:
                # Block period expired, reset attempts
                attempts_data[ip_address]['attempts'] = 0
                save_failed_attempts(attempts_data)
    
    return False

def record_failed_attempt(username, ip_address):
    attempts_data = load_failed_attempts()
    now = datetime.now().isoformat()
    
    # Track by username
    if username in attempts_data:
        attempts_data[username]['attempts'] += 1
        attempts_data[username]['timestamp'] = now
    else:
        attempts_data[username] = {'attempts': 1, 'timestamp': now}
    
    # Track by IP address
    if ip_address in attempts_data:
        attempts_data[ip_address]['attempts'] += 1
        attempts_data[ip_address]['timestamp'] = now
    else:
        attempts_data[ip_address] = {'attempts': 1, 'timestamp': now}
    
    save_failed_attempts(attempts_data)

@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.get_json()
    username = data.get('username')

    with open('users.json', 'r') as f:
        users = json.load(f)

    for user in users:
        if user['username'].lower() == username.lower():
            return jsonify({'available': False})  # Username taken

    return jsonify({'available': True})  # Username is available


if __name__ == '__main__':
    # Create required files if they don't exist
    for file in [USERS_FILE, PENDING_FILE, DECLINED_FILE]:
        if not os.path.exists(file):
            save_json([], file)
    
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    app.run(host="0.0.0.0", port=5000, debug=True)
