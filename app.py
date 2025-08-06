from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
from base64 import b64decode
from datetime import datetime
import os
import uuid
import io
import pandas as pd
from dotenv import load_dotenv
from supabase import create_client, Client

# Carga de .env
load_dotenv()

# Configuración de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# SocketIO (threading para compatibilidad en Render)
socketio = SocketIO(app, async_mode='threading')

# Cliente Supabase
supabase: Client = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))

# Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# --- Utilidades ---
def convertir_fechas(solicitud):
    """Convierte campos de fecha de string a datetime."""
    if 'fecha_creacion' in solicitud and isinstance(solicitud['fecha_creacion'], str):
        solicitud['fecha_creacion'] = datetime.fromisoformat(solicitud['fecha_creacion'])
    if 'fecha_finalizacion' in solicitud and isinstance(solicitud['fecha_finalizacion'], str):
        solicitud['fecha_finalizacion'] = datetime.fromisoformat(solicitud['fecha_finalizacion']) if solicitud['fecha_finalizacion'] else None
    return solicitud

# --- Modelo User ---
class User(UserMixin):
    def __init__(self, id, username, password, role, nombre, email):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.nombre = nombre
        self.email = email

    @staticmethod
    def get(user_id):
        resp = supabase.table("users").select("*").eq("id", user_id).execute()
        if resp.data:
            u = resp.data[0]
            return User(u['id'], u['username'], u['password'], u['role'], u['nombre'], u['email'])
        return None

    @staticmethod
    def get_by_username(username):
        resp = supabase.table("users").select("*").eq("username", username).execute()
        if resp.data:
            u = resp.data[0]
            return User(u['id'], u['username'], u['password'], u['role'], u['nombre'], u['email'])
        return None

    @staticmethod
    def get_tecnicos():
        resp = supabase.table("users").select("*").eq("role", "tecnico").execute()
        return resp.data or []

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Rutas de Autenticación ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.get_by_username(request.form['username'])
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            flash('Bienvenido', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'tecnico':
                return redirect(url_for('tecnico_dashboard'))
            elif user.role == 'user':
                return redirect(url_for('user_dashboard'))
        flash('Credenciales inválidas', 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada", "info")
    return redirect(url_for('login'))

# --- Dashboards ---
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('login'))

    resp = supabase.table('solicitud').select('*').order('fecha_creacion', desc=True).execute()
    solicitudes = [convertir_fechas(s) for s in resp.data] if resp.data else []

    # Enriquecer con datos de usuario
    for s in solicitudes:
        u = supabase.table('users').select('nombre').eq('id', s['usuario_id']).execute().data
        s['usuario'] = u[0] if u else {'nombre': 'Desconocido'}
    return render_template('admin/dashboard.html', solicitudes=solicitudes)

@app.route('/tecnico/dashboard')
@login_required
def tecnico_dashboard():
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))
    
    # Obtener solicitudes asignadas al técnico
    asignaciones = supabase.table('asignaciones_tecnicos') \
                         .select('solicitud_id') \
                         .eq('tecnico_id', current_user.id) \
                         .execute().data
    solicitudes_ids = [a['solicitud_id'] for a in asignaciones]
    
    if solicitudes_ids:
        resp = supabase.table('solicitud') \
                     .select('*') \
                     .in_('id', solicitudes_ids) \
                     .execute()
        solicitudes = [convertir_fechas(s) for s in resp.data] if resp.data else []
    else:
        solicitudes = []
    
    return render_template('tecnico/dashboard.html', solicitudes=solicitudes)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('login'))
    
    resp = supabase.table('solicitud') \
                 .select('*') \
                 .eq('usuario_id', current_user.id) \
                 .order('fecha_creacion', desc=True) \
                 .execute()
    solicitudes = [convertir_fechas(s) for s in resp.data] if resp.data else []
    return render_template('user/dashboard.html', solicitudes=solicitudes)

# --- Punto de arranque ---
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
