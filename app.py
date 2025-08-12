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

# Cargar variables de entorno
load_dotenv()

# Configuración de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# SocketIO
socketio = SocketIO(app, async_mode='threading')

# Cliente Supabase
supabase: Client = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))

# Login Manager
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Notificaciones
def notificar_tecnicos_y_admins(mensaje, tipo='info'):
    socketio.emit('nueva_notificacion', {
        'mensaje': mensaje,
        'tipo': tipo,
        'timestamp': datetime.utcnow().isoformat()
    })

# Modelo de usuario
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

    @staticmethod
    def all():
        resp = supabase.table("users").select("*").order("role").order("nombre").execute()
        return resp.data or []

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
# Ruta de login
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)

        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'tecnico':
                return redirect(url_for('tecnico_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Usuario o contraseña incorrectos', 'danger')
    return render_template('auth/login.html')

# Ruta de registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']

        if User.get_by_username(username):
            flash('El nombre de usuario ya existe.', 'danger')
            return redirect(url_for('registro'))

        hashed_password = generate_password_hash(password)
        user_data = {
            "username": username,
            "nombre": nombre,
            "email": email,
            "password": hashed_password,
            "role": "user"
        }
        supabase.table("users").insert(user_data).execute()
        flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/registro.html')

# Dashboard administrador
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    resp = supabase.table('solicitud').select('*').order('fecha_creacion', desc=True).execute()
    solicitudes = resp.data or []

    for s in solicitudes:
        if isinstance(s.get("fecha_creacion"), str):
            try:
                s["fecha_creacion"] = datetime.fromisoformat(s["fecha_creacion"].replace("Z", ""))
            except:
                pass
        if isinstance(s.get("fecha_finalizacion"), str):
            try:
                s["fecha_finalizacion"] = datetime.fromisoformat(s["fecha_finalizacion"].replace("Z", ""))
            except:
                pass

        u = supabase.table('users').select('nombre').eq('id', s['usuario_id']).execute().data
        s['usuario'] = u[0] if u else {'nombre': 'Desconocido'}

        asignados = supabase.table("asignaciones_tecnicos").select("tecnico_id").eq("solicitud_id", s["id"]).execute()
        tecnicos = []
        for asignacion in asignados.data or []:
            tecnico = supabase.table("users").select("nombre").eq("id", asignacion["tecnico_id"]).execute().data
            if tecnico:
                tecnicos.append({"nombre": tecnico[0]["nombre"]})
        s["tecnicos_asignados"] = tecnicos

    return render_template('admin/dashboard.html', solicitudes=solicitudes)

# Dashboard usuario
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('login'))

    resp = supabase.table('solicitud').select('*').eq('usuario_id', current_user.id).order('fecha_creacion', desc=True).execute()
    solicitudes = resp.data or []

    for s in solicitudes:
        if isinstance(s.get("fecha_creacion"), str):
            try:
                s["fecha_creacion"] = datetime.fromisoformat(s["fecha_creacion"].replace("Z", ""))
            except:
                pass
        if isinstance(s.get("fecha_finalizacion"), str):
            try:
                s["fecha_finalizacion"] = datetime.fromisoformat(s["fecha_finalizacion"].replace("Z", ""))
            except:
                pass

    return render_template('user/dashboard.html', solicitudes=solicitudes)

# Dashboard técnico
@app.route('/tecnico/dashboard')
@login_required
def tecnico_dashboard():
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))

    asignaciones = supabase.table("asignaciones_tecnicos").select("solicitud_id").eq("tecnico_id", current_user.id).execute()
    solicitudes_ids = [a["solicitud_id"] for a in asignaciones.data or []]

    solicitudes = []
    if solicitudes_ids:
        resp = supabase.table("solicitud").select("*").in_("id", solicitudes_ids).execute()
        solicitudes = resp.data or []

        for s in solicitudes:
            if isinstance(s.get("fecha_creacion"), str):
                try:
                    s["fecha_creacion"] = datetime.fromisoformat(s["fecha_creacion"].replace("Z", ""))
                except:
                    pass
            if isinstance(s.get("fecha_finalizacion"), str):
                try:
                    s["fecha_finalizacion"] = datetime.fromisoformat(s["fecha_finalizacion"].replace("Z", ""))
                except:
                    pass

    return render_template('tecnico/dashboard.html', solicitudes=solicitudes)
# Crear nueva solicitud (usuario)
@app.route('/user/solicitud', methods=['GET', 'POST'])
@login_required
def nueva_solicitud():
    if current_user.role != 'user':
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = {
            'tipo_trabajo': request.form['tipo_trabajo'],
            'tipo_actividad': request.form['tipo_actividad'],
            'descripcion': request.form['descripcion'],
            'ubicacion': request.form['ubicacion'],
            'prioridad': request.form['prioridad'],
            'estado': 'Pendiente',
            'usuario_id': current_user.id,
            'fecha_creacion': datetime.utcnow().isoformat()
        }
        supabase.table('solicitud').insert(data).execute()
        notificar_tecnicos_y_admins('Nueva solicitud creada')
        flash('Solicitud enviada correctamente.', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('user/solicitud.html')

# Asignar técnicos a solicitud (admin)
@app.route('/admin/solicitud/<int:solicitud_id>/asignar', methods=['GET', 'POST'])
@login_required
def asignar_tecnicos(solicitud_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        tecnicos_ids = request.form.getlist('tecnicos')
        supabase.table("asignaciones_tecnicos").delete().eq("solicitud_id", solicitud_id).execute()
        for tid in tecnicos_ids:
            supabase.table("asignaciones_tecnicos").insert({
                "solicitud_id": solicitud_id,
                "tecnico_id": tid
            }).execute()
        flash('Técnicos asignados correctamente.', 'success')
        return redirect(url_for('admin_dashboard'))

    tecnicos = User.get_tecnicos()
    return render_template('admin/asignar_tecnicos.html', solicitud_id=solicitud_id, tecnicos=tecnicos)

# Subir evidencia (técnico)
@app.route('/tecnico/solicitud/<int:solicitud_id>/evidencia', methods=['POST'])
@login_required
def subir_evidencia(solicitud_id):
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))

    if 'foto' in request.files:
        foto = request.files['foto']
        if foto.filename != '':
            filename = secure_filename(foto.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto.save(filepath)
            supabase.table('solicitud').update({"foto": filename}).eq("id", solicitud_id).execute()

    flash('Evidencia subida correctamente.', 'success')
    return redirect(url_for('tecnico_dashboard'))

# Subir firma (técnico en cierre)
@app.route('/tecnico/solicitud/<int:solicitud_id>/firma', methods=['POST'])
@login_required
def subir_firma(solicitud_id):
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))

    if 'firma' in request.form:
        firma_data = request.form['firma'].split(',')[1]
        firma_bytes = b64decode(firma_data)
        filename = f"firma_{uuid.uuid4().hex}.png"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, "wb") as f:
            f.write(firma_bytes)
        supabase.table('solicitud').update({"firma": filename}).eq("id", solicitud_id).execute()

    flash('Firma subida correctamente.', 'success')
    return redirect(url_for('tecnico_dashboard'))

# Cambiar estado de solicitud (técnico)
@app.route('/tecnico/solicitud/<int:solicitud_id>/estado', methods=['POST'])
@login_required
def cambiar_estado_solicitud(solicitud_id):
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))

    nuevo_estado = request.form.get('estado')
    data_update = {"estado": nuevo_estado}

    if nuevo_estado.lower() == 'finalizado':
        data_update["fecha_finalizacion"] = datetime.utcnow().isoformat()

    supabase.table('solicitud').update(data_update).eq("id", solicitud_id).execute()
    flash('Estado actualizado correctamente.', 'success')
    return redirect(url_for('tecnico_dashboard'))
# Editar solicitud (admin)
@app.route('/admin/solicitud/editar/<int:solicitud_id>', methods=['GET', 'POST'])
@login_required
def editar_solicitud(solicitud_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        update_data = {
            'tipo_trabajo': request.form['tipo_trabajo'],
            'tipo_actividad': request.form['tipo_actividad'],
            'descripcion': request.form['descripcion'],
            'ubicacion': request.form['ubicacion'],
            'prioridad': request.form['prioridad'],
            'estado': request.form['estado']
        }
        supabase.table('solicitud').update(update_data).eq('id', solicitud_id).execute()
        flash('Solicitud actualizada correctamente.', 'success')
        return redirect(url_for('admin_dashboard'))

    solicitud = supabase.table('solicitud').select('*').eq('id', solicitud_id).execute().data
    return render_template('admin/editar_solicitud.html', solicitud=solicitud[0] if solicitud else None)

# Eliminar solicitud (admin)
@app.route('/admin/solicitud/eliminar/<int:solicitud_id>', methods=['POST'])
@login_required
def eliminar_solicitud(solicitud_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    supabase.table('solicitud').delete().eq('id', solicitud_id).execute()
    supabase.table("asignaciones_tecnicos").delete().eq("solicitud_id", solicitud_id).execute()
    flash('Solicitud eliminada correctamente.', 'success')
    return redirect(url_for('admin_dashboard'))

# Exportar solicitudes a Excel (admin)
@app.route('/admin/exportar')
@login_required
def exportar_solicitudes():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    resp = supabase.table('solicitud').select('*').execute()
    solicitudes = resp.data or []
    df = pd.DataFrame(solicitudes)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Solicitudes')

    output.seek(0)
    return send_file(output, download_name='solicitudes.xlsx', as_attachment=True)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Arranque
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
