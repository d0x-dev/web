import os

# Secret key for session management
SECRET_KEY = 'd2f8a9d4e7b1c6f3e8a5b2d9f4c7e1b6a8d3f5e2c9b1a7f6d4e9c2b5a8f3d1e6'

# Database configuration
DATABASE = 'school.db'

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png'}

# Admin login attempts
MAX_LOGIN_ATTEMPTS = 5

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
