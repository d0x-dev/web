from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import sqlite3
from functools import wraps

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.secret_key = app.config['SECRET_KEY']

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
                date TEXT NOT NULL
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

# Auth decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in to access admin panel', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    conn = get_db_connection()
    pinned_notices = conn.execute('SELECT * FROM notifications WHERE is_pinned = 1 ORDER BY date_posted DESC LIMIT 2').fetchall()
    recent_syllabus = conn.execute('SELECT * FROM syllabus ORDER BY upload_date DESC LIMIT 2').fetchall()
    conn.close()
    return render_template('index.html', pinned_notices=pinned_notices, recent_syllabus=recent_syllabus)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/documents')
def documents():
    conn = get_db_connection()
    documents = conn.execute('SELECT * FROM documents ORDER BY upload_date DESC').fetchall()
    conn.close()
    return render_template('documents.html', documents=documents)

@app.route('/syllabus')
def syllabus():
    conn = get_db_connection()
    syllabus = conn.execute('''
        SELECT * FROM syllabus 
        ORDER BY year DESC, class_name ASC, subject ASC
    ''').fetchall()
    conn.close()
    return render_template('syllabus.html', syllabus=syllabus)

@app.route('/notifications')
def notifications():
    conn = get_db_connection()
    notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC').fetchall()
    conn.close()
    return render_template('notifications.html', notifications=notifications)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            email = request.form.get('email')
            subject = request.form.get('subject')
            message = request.form.get('message')
            
            if not all([name, email, subject, message]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('contact'))
            
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
    feedbacks = conn.execute('SELECT * FROM feedback ORDER BY date DESC').fetchall()
    conn.close()
    return render_template('admin/dashboard.html', feedbacks=feedbacks)

@app.route('/admin/notifications', methods=['GET', 'POST'])
@admin_required
def admin_notifications():
    conn = get_db_connection()
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_pinned = 1 if request.form.get('is_pinned') else 0
        date_posted = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn.execute(
            'INSERT INTO notifications (title, content, date_posted, is_pinned) VALUES (?, ?, ?, ?)',
            (title, content, date_posted, is_pinned)
        )
        conn.commit()
        flash('Notification added successfully!', 'success')
    
    notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC').fetchall()
    conn.close()
    return render_template('admin/notifications.html', notifications=notifications)

@app.route('/admin/upload_syllabus', methods=['GET', 'POST'])
@admin_required
def upload_syllabus():
    if request.method == 'POST':
        try:
            class_name = request.form.get('class_name')
            year = request.form.get('year')
            month = request.form.get('month')
            exam_name = request.form.get('exam_name')
            subject = request.form.get('subject')
            file = request.files.get('file')
            
            if not all([class_name, year, month, exam_name, subject, file]):
                flash('Please fill all required fields', 'danger')
                return redirect(url_for('upload_syllabus'))
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                conn = get_db_connection()
                conn.execute(
                    'INSERT INTO syllabus (class_name, year, month, exam_name, subject, filename, upload_date) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (class_name, year, month, exam_name, subject, filename, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                conn.commit()
                conn.close()
                
                flash('Syllabus uploaded successfully!', 'success')
                return redirect(url_for('syllabus'))
            else:
                flash('Invalid file type', 'danger')
        except Exception as e:
            print(f"Error uploading syllabus: {e}")
            flash('An error occurred while uploading syllabus', 'danger')
    
    return render_template('admin/upload_syllabus.html')

@app.route('/admin/delete_notification/<int:id>')
@admin_required
def delete_notification(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM notifications WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Notification deleted successfully!', 'success')
    return redirect(url_for('admin_notifications'))

@app.route('/admin/upload_document', methods=['POST'])
@admin_required
def upload_document():
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO documents (name, category, filename, upload_date) VALUES (?, ?, ?, ?)',
            (request.form['name'], request.form['category'], filename, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        
        flash('Document uploaded successfully!', 'success')
    else:
        flash('Invalid file type', 'danger')
    
    return redirect(url_for('admin_dashboard'))

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
        admin = conn.execute('SELECT * FROM admin WHERE username = ?', (session['admin_username'],)).fetchone()
        
        if not check_password_hash(admin['password'], current_password):
            flash('Current password is incorrect', 'danger')
            conn.close()
            return redirect(url_for('change_password'))
        
        conn.execute(
            'UPDATE admin SET password = ? WHERE username = ?',
            (generate_password_hash(new_password), session['admin_username'])
        )
        conn.commit()
        conn.close()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/change_password.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
