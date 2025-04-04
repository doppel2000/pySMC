import os
import secrets
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or "65AA8F6BE24DE91AFEE71664DEE7234C"

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
    
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') or 1
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'app.pysmc@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'rnpgnkeofrqmndmq'
    ADMINS = ['app.pysmc@gmail.com']

    FLASK_ADMIN_FLUID_LAYOUT = True
    FLASK_ADMIN_SWATCH = 'lumen'
    
    LOCAL_TIMEZONE = 'Europe/Brussels'

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # Disable time-based expiration
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY') or "5AC115B81042066F9E6E13D5BC05E1CE"

    PERMANENT_SESSION_LIFETIME = timedelta(hours=4)
    
    UPLOAD_FOLDER = "uploads"
    OUTPUT_FOLDER = "outputs"
    ALLOWED_EXTENSIONS = {'xlsx'}
