import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'tu_clave_secreta_aqui'
    UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')

MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB máximo
