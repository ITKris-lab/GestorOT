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

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

socketio = SocketIO(app, async_mode='threading')

# Supabase client
supabase: Client = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))

# Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ===================== UTILIDAD =====================
def notificar_tecnicos_y_admins(mensaje, tipo='info'):
    socketio.emit('nueva_notificacion', {
        'mensaje': mensaje,
        'tipo': tipo,
        'timestamp': datetime.utcnow().isoformat()
    })

# ===================== USUARIO =====================
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
        result = supabase.table("users").select("*").eq("id", user_id).execute()
        if result.data:
            u = result.data[0]
            return User(u['id'], u['username'], u['password'], u['role'], u['nombre'], u['email'])
        return None

    @staticmethod
    def get_by_username(username):
        result = supabase.table("users").select("*").eq("username", username).execute()
        if result.data:
            u = result.data[0]
            return User(u['id'], u['username'], u['password'], u['role'], u['nombre'], u['email'])
        return None

    @staticmethod
    def get_tecnicos():
        result = supabase.table("users").select("*").eq("role", "tecnico").execute()
        return result.data or []

    @staticmethod
    def all():
        result = supabase.table("users").select("*").order("role").order("nombre").execute()
        return result.data or []

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

from flask_login import login_user, logout_user, login_required, current_user, UserMixin

# -------------------
# MODELO DE USUARIO
# -------------------

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
        response = supabase.table('users').select('*').eq('id', user_id).single().execute()
        if response.data:
            data = response.data
            return User(data['id'], data['username'], data['password'], data['role'], data['nombre'], data['email'])
        return None

    @staticmethod
    def get_by_username(username):
        response = supabase.table('users').select('*').eq('username', username).single().execute()
        if response.data:
            data = response.data
            return User(data['id'], data['username'], data['password'], data['role'], data['nombre'], data['email'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# -------------------
# AUTENTICACIÓN
# -------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Bienvenido', 'success')
            return redirect(url_for(f"{user.role}_dashboard"))
        flash('Credenciales inválidas', 'danger')
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        nombre = request.form['nombre']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        if User.get_by_username(username):
            flash('El nombre de usuario ya existe.', 'danger')
            return redirect(url_for('register'))

        response = supabase.table('users').insert({
            'username': username,
            'nombre': nombre,
            'email': email,
            'password': password,
            'role': role
        }).execute()

        flash('Usuario registrado correctamente.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada", "info")
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

# -------------------
# DASHBOARD POR ROL
# -------------------

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('login'))

    response = supabase.table('solicitudes').select('*').order('fecha_creacion', desc=True).execute()
    solicitudes = response.data if response.data else []
    return render_template('admin/dashboard.html', solicitudes=solicitudes)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('login'))

    response = supabase.table('solicitudes').select('*').eq('usuario_id', current_user.id).order('fecha_creacion', desc=True).execute()
    solicitudes = response.data if response.data else []
    return render_template('user/dashboard.html', solicitudes=solicitudes)

@app.route('/tecnico/dashboard')
@login_required
def tecnico_dashboard():
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))

    response = supabase.rpc('solicitudes_por_tecnico', {'tecnico_id': current_user.id}).execute()
    solicitudes = response.data if response.data else []
    return render_template('tecnico/dashboard.html', solicitudes=solicitudes)
    
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

        # Subida de imagen
        foto = request.files.get('foto')
        if foto and foto.filename:
            nombre_archivo = f"{uuid.uuid4().hex}_{secure_filename(foto.filename)}"
            ruta = os.path.join(app.config['UPLOAD_FOLDER'], nombre_archivo)
            foto.save(ruta)
            data['foto'] = nombre_archivo

        response = supabase.table('solicitudes').insert(data).execute()
        if response.error:
            flash('Error al crear la solicitud', 'danger')
        else:
            flash('Solicitud creada exitosamente', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('user/solicitud.html')
    
@app.route('/admin/asignar_tecnicos/<int:solicitud_id>', methods=['GET', 'POST'])
@login_required
def asignar_tecnicos(solicitud_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    solicitud = supabase.table('solicitudes').select('*').eq('id', solicitud_id).single().execute().data
    tecnicos = supabase.table('users').select('*').eq('role', 'tecnico').execute().data

    if request.method == 'POST':
        seleccionados = request.form.getlist('tecnicos')
        for tecnico_id in seleccionados:
            supabase.table('asignaciones_tecnicos').insert({
                'solicitud_id': solicitud_id,
                'tecnico_id': int(tecnico_id)
            }).execute()

        # Emitir notificación vía SocketIO
        mensaje = f"Nueva solicitud asignada: #{solicitud_id} - {solicitud['tipo_trabajo']}"
        for tecnico_id in seleccionados:
            socketio.emit('nueva_asignacion', {
                'tecnico_id': int(tecnico_id),
                'mensaje': mensaje,
                'tipo': 'asignacion',
                'timestamp': datetime.utcnow().isoformat()
            })

        flash("Técnicos asignados correctamente", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/asignar_tecnicos.html', solicitud=solicitud, tecnicos=tecnicos)

@app.route('/admin/solicitud/eliminar/<int:solicitud_id>', methods=['POST'])
@login_required
def eliminar_solicitud(solicitud_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    solicitud = supabase.table('solicitudes').select('*').eq('id', solicitud_id).single().execute().data
    if solicitud.get('foto'):
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], solicitud['foto']))
        except:
            pass
    if solicitud.get('firma'):
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], solicitud['firma']))
        except:
            pass

    supabase.table('solicitudes').delete().eq('id', solicitud_id).execute()
    flash("Solicitud eliminada", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/tecnico/orden/<int:id>', methods=['GET', 'POST'])
@login_required
def gestion_orden(id):
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))

    solicitud = supabase.table('solicitudes').select('*').eq('id', id).single().execute().data

    if request.method == 'POST':
        update_data = {
            'estado': request.form['estado'],
            'fecha_finalizacion': datetime.utcnow().isoformat()
        }

        evidencia = request.files.get('evidencia')
        if evidencia and evidencia.filename:
            filename = f"evidencia_{uuid.uuid4().hex}_{secure_filename(evidencia.filename)}"
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            evidencia.save(path)
            update_data['foto'] = filename

        firma = request.form.get('firma')
        if firma and firma.startswith("data:image/png;base64,"):
            firma_bin = b64decode(firma.split(",")[1])
            firma_nombre = f"firma_{uuid.uuid4().hex}.png"
            ruta_firma = os.path.join(app.config['UPLOAD_FOLDER'], firma_nombre)
            with open(ruta_firma, "wb") as f:
                f.write(firma_bin)
            update_data['firma'] = firma_nombre

        supabase.table('solicitudes').update(update_data).eq('id', id).execute()

        mensaje = f"La solicitud #{id} ha cambiado de estado a: {update_data['estado']}"
        notificar_tecnicos_y_admins(mensaje, 'estado')

        flash('Solicitud actualizada correctamente', 'success')
        return redirect(url_for('tecnico_dashboard'))

    return render_template('tecnico/orden.html', solicitud=solicitud)

@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    usuarios = supabase.table('users').select('*').order('role').execute().data
    return render_template('admin/usuarios.html', usuarios=usuarios)

@app.route('/admin/usuarios/nuevo', methods=['GET', 'POST'])
@login_required
def admin_usuario_nuevo():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        datos = {
            'username': request.form['username'],
            'nombre': request.form['nombre'],
            'email': request.form['email'],
            'role': request.form['role'],
            'password': generate_password_hash(request.form['password'])
        }
        existing = supabase.table('users').select('id').eq('username', datos['username']).execute().data
        if existing:
            flash('El usuario ya existe', 'warning')
            return redirect(url_for('admin_usuario_nuevo'))

        supabase.table('users').insert(datos).execute()
        flash('Usuario creado correctamente', 'success')
        return redirect(url_for('admin_usuarios'))

    return render_template('admin/usuario_form.html', accion='Nuevo')

@app.route('/admin/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_usuario_editar(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    user = supabase.table('users').select('*').eq('id', user_id).single().execute().data

    if request.method == 'POST':
        actualizacion = {
            'username': request.form['username'],
            'nombre': request.form['nombre'],
            'email': request.form['email'],
            'role': request.form['role']
        }
        if request.form['password']:
            actualizacion['password'] = generate_password_hash(request.form['password'])

        supabase.table('users').update(actualizacion).eq('id', user_id).execute()
        flash('Usuario actualizado correctamente', 'success')
        return redirect(url_for('admin_usuarios'))

    return render_template('admin/usuario_form.html', accion='Editar', user=user)

@app.route('/admin/usuarios/eliminar/<int:user_id>', methods=['POST'])
@login_required
def admin_usuario_eliminar(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    supabase.table('users').delete().eq('id', user_id).execute()
    flash('Usuario eliminado', 'success')
    return redirect(url_for('admin_usuarios'))

@app.route('/reportes', methods=['GET', 'POST'])
@login_required
def reportes():
    if current_user.role not in ['admin', 'tecnico']:
        return redirect(url_for('login'))

    estado = request.form.get('estado', 'Todos')
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')

    query = supabase.table('solicitudes').select('*')
    if estado != 'Todos':
        query = query.eq('estado', estado)
    if fecha_inicio:
        query = query.gte('fecha_creacion', fecha_inicio)
    if fecha_fin:
        query = query.lte('fecha_creacion', fecha_fin)

    solicitudes = query.execute().data

    return render_template('reportes.html', solicitudes=solicitudes)

@app.route('/reportes/exportar_excel', methods=['POST'])
@login_required
def exportar_excel():
    if current_user.role not in ['admin', 'tecnico']:
        return redirect(url_for('login'))

    estado = request.form.get('estado', 'Todos')
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin = request.form.get('fecha_fin')

    query = supabase.table('solicitudes').select('*')
    if estado != 'Todos':
        query = query.eq('estado', estado)
    if fecha_inicio:
        query = query.gte('fecha_creacion', fecha_inicio)
    if fecha_fin:
        query = query.lte('fecha_creacion', fecha_fin)

    datos = query.execute().data

    df = pd.DataFrame(datos)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    output.seek(0)

    filename = f"reportes_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(output, as_attachment=True, download_name=filename, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/verificar_usuario')
def verificar_usuario():
    username = request.args.get('username')
    exists = supabase.table('user').select('id').eq('username', username).execute().data
    return {'exists': bool(exists)}

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        emit('usuario_conectado', {'id': current_user.id, 'rol': current_user.role})

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        emit('usuario_desconectado', {'id': current_user.id, 'rol': current_user.role})

# Usuario admin por defecto (solo si no existe)
with app.app_context():
    res = supabase.table("users").select("*").eq("username", "admin").execute()
    if not res.data:
        admin = {
            "username": "admin",
            "password": generate_password_hash("admin123"),
            "nombre": "Administrador del Sistema",
            "email": "admin@hospital.cl",
            "role": "admin"
        }
        supabase.table("users").insert(admin).execute()
        print("✅ Usuario admin creado con éxito.")
    else:
        print("ℹ️ Usuario admin ya existe.")

        
