import os

# Secret key for session management
SECRET_KEY = 'your-very-secret-key-here-change-this-in-production'

# Database configuration
DATABASE = 'school.db'

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png'}

# Admin login attempts
MAX_LOGIN_ATTEMPTS = 5

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
