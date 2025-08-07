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

# Utilidad de notificaciones
def notificar_tecnicos_y_admins(mensaje, tipo='info'):
    socketio.emit('nueva_notificacion', {
        'mensaje': mensaje,
        'tipo': tipo,
        'timestamp': datetime.utcnow().isoformat()
    })

# Modelo de usuario usando Supabase
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
        resp = supabase.table("users") \
                       .select("*") \
                       .eq("id", user_id) \
                       .execute()
        if resp.data:
            u = resp.data[0]
            return User(u['id'], u['username'], u['password'],
                        u['role'], u['nombre'], u['email'])
        return None

    @staticmethod
    def get_by_username(username):
        resp = supabase.table("users") \
                       .select("*") \
                       .eq("username", username) \
                       .execute()
        if resp.data:
            u = resp.data[0]
            return User(u['id'], u['username'], u['password'],
                        u['role'], u['nombre'], u['email'])
        return None

    @staticmethod
    def get_tecnicos():
        resp = supabase.table("users") \
                       .select("*") \
                       .eq("role", "tecnico") \
                       .execute()
        return resp.data or []

    @staticmethod
    def all():
        resp = supabase.table("users") \
                       .select("*") \
                       .order("role") \
                       .order("nombre") \
                       .execute()
        return resp.data or []

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Rutas de autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
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
        except Exception as e:
            flash('Error al iniciar sesión', 'danger')
            print(f"Error en login: {e}")  # Para ver el error en los logs de Render
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        if User.get_by_username(username):
            flash('El nombre de usuario ya existe.', 'danger')
            return redirect(url_for('register'))

        nueva = {
            'username': username,
            'nombre': request.form['nombre'],
            'email': request.form['email'],
            'password': generate_password_hash(request.form['password']),
            'role': request.form['role']
        }
        supabase.table('users').insert(nueva).execute()
        flash('Usuario registrado correctamente.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada", "info")
    return redirect(url_for('login'))

# Ruta raíz redirige a login
@app.route('/')
def index():
    return redirect(url_for('login'))

# Dashboards por rol
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Acceso denegado", "danger")
        return redirect(url_for('login'))

    resp = supabase.table('solicitud').select('*') \
                   .order('fecha_creacion', desc=True).execute()
    solicitudes = resp.data or []

    # Convertir fechas de strings a objetos datetime
    for s in solicitudes:
        if 'fecha_creacion' in s and isinstance(s['fecha_creacion'], str):
            s['fecha_creacion'] = datetime.fromisoformat(s['fecha_creacion'])
        if 'fecha_finalizacion' in s and isinstance(s['fecha_finalizacion'], str):
            s['fecha_finalizacion'] = datetime.fromisoformat(s['fecha_finalizacion']) if s['fecha_finalizacion'] else None

        # Enriquecer con usuario y técnicos asignados
        u = supabase.table('users').select('nombre').eq('id', s['usuario_id']).execute().data
        s['usuario'] = u[0] if u else {'nombre': 'Desconocido'}
        asigns = supabase.table('asignaciones_tecnicos') \
                         .select('tecnico_id') \
                         .eq('solicitud_id', s['id']).execute().data
        s['tecnicos_asignados'] = []
        for a in asigns:
            t = supabase.table('users').select('nombre').eq('id', a['tecnico_id']).execute().data
            if t: s['tecnicos_asignados'].append(t[0])
    return render_template('admin/dashboard.html', solicitudes=solicitudes)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('login'))
    resp = supabase.table('solicitudes') \
                   .select('*') \
                   .eq('usuario_id', current_user.id) \
                   .order('fecha_creacion', desc=True) \
                   .execute()
    solicitudes = resp.data or []
    
    # Convertir fechas de strings a objetos datetime
    for s in solicitudes:
        if 'fecha_creacion' in s and isinstance(s['fecha_creacion'], str):
            s['fecha_creacion'] = datetime.fromisoformat(s['fecha_creacion'])
        if 'fecha_finalizacion' in s and isinstance(s['fecha_finalizacion'], str):
            s['fecha_finalizacion'] = datetime.fromisoformat(s['fecha_finalizacion']) if s['fecha_finalizacion'] else None
            
    return render_template('user/dashboard.html', solicitudes=solicitudes)

@app.route('/tecnico/dashboard')
@login_required
def tecnico_dashboard():
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))
    resp = supabase.rpc('solicitudes_por_tecnico', {'tecnico_id': current_user.id}).execute()
    solicitudes = resp.data or []
    
    # Convertir fechas de strings a objetos datetime
    for s in solicitudes:
        if 'fecha_creacion' in s and isinstance(s['fecha_creacion'], str):
            s['fecha_creacion'] = datetime.fromisoformat(s['fecha_creacion'])
        if 'fecha_finalizacion' in s and isinstance(s['fecha_finalizacion'], str):
            s['fecha_finalizacion'] = datetime.fromisoformat(s['fecha_finalizacion']) if s['fecha_finalizacion'] else None
            
    return render_template('tecnico/dashboard.html', solicitudes=solicitudes)

# Crear nueva solicitud
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
        foto = request.files.get('foto')
        if foto and foto.filename:
            fn = f"{uuid.uuid4().hex}_{secure_filename(foto.filename)}"
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], fn))
            data['foto'] = fn
        supabase.table('solicitud').insert(data).execute()
        flash('Solicitud creada exitosamente', 'success')
        return redirect(url_for('user_dashboard'))
    return render_template('user/solicitud.html')

# Asignar técnicos (admin)
@app.route('/admin/asignar_tecnicos/<int:solicitud_id>', methods=['GET', 'POST'])
@login_required
def asignar_tecnicos(solicitud_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    resp = supabase.table('solicitud').select('*').eq('id', solicitud_id).execute()
    solicitud = resp.data[0] if resp.data else None
    tecnicos = User.get_tecnicos()
    if request.method == 'POST':
        seleccionados = request.form.getlist('tecnicos')
        for tid in seleccionados:
            supabase.table('asignaciones_tecnicos').insert({
                'solicitud_id': solicitud_id,
                'tecnico_id': int(tid)
            }).execute()
        msg = f"Nueva solicitud asignada: #{solicitud_id} - {solicitud['tipo_trabajo']}"
        for tid in seleccionados:
            socketio.emit('nueva_asignacion', {
                'tecnico_id': int(tid),
                'mensaje': msg,
                'tipo': 'asignacion',
                'timestamp': datetime.utcnow().isoformat()
            })
        flash("Técnicos asignados correctamente", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/asignar_tecnicos.html',
                           solicitud=solicitud, tecnicos=tecnicos)

# Eliminar solicitud (admin)
@app.route('/admin/solicitud/eliminar/<int:solicitud_id>', methods=['POST'])
@login_required
def eliminar_solicitud(solicitud_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    resp = supabase.table('solicitud').select('*').eq('id', solicitud_id).execute()
    s = resp.data[0] if resp.data else {}
    for fld in ('foto', 'firma'):
        fn = s.get(fld)
        if fn:
            try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], fn))
            except: pass
    supabase.table('solicitud').delete().eq('id', solicitud_id).execute()
    flash("Solicitud eliminada", "success")
    return redirect(url_for('admin_dashboard'))

# Gestionar orden (técnico)
@app.route('/tecnico/orden/<int:id>', methods=['GET', 'POST'])
@login_required
def gestion_orden(id):
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))
    resp = supabase.table('solicitud').select('*').eq('id', id).execute()
    s = resp.data[0] if resp.data else None
    if request.method == 'POST':
        ud = {
            'estado': request.form['estado'],
            'fecha_finalizacion': datetime.utcnow().isoformat()
        }
        ev = request.files.get('evidencia')
        if ev and ev.filename:
            fn = f"evidencia_{uuid.uuid4().hex}_{secure_filename(ev.filename)}"
            ev.save(os.path.join(app.config['UPLOAD_FOLDER'], fn))
            ud['foto'] = fn
        firma = request.form.get('firma')
        if firma and firma.startswith("data:image/png;base64,"):
            bin_data = b64decode(firma.split(",")[1])
            fn = f"firma_{uuid.uuid4().hex}.png"
            with open(os.path.join(app.config['UPLOAD_FOLDER'], fn), "wb") as f:
                f.write(bin_data)
            ud['firma'] = fn
        supabase.table('solicitud').update(ud).eq('id', id).execute()
        notificar_tecnicos_y_admins(
            f"La solicitud #{id} cambió a {ud['estado']}", 'estado'
        )
        flash('Solicitud actualizada correctamente', 'success')
        return redirect(url_for('tecnico_dashboard'))
    return render_template('tecnico/orden.html', solicitud=s)

# Gestión de usuarios (admin)
@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    users = supabase.table('users').select('*').order('role').execute().data or []
    return render_template('admin/usuarios.html', usuarios=users)

@app.route('/admin/usuarios/nuevo', methods=['GET', 'POST'])
@login_required
def admin_usuario_nuevo():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        u = {
            'username': request.form['username'],
            'nombre': request.form['nombre'],
            'email': request.form['email'],
            'role': request.form['role'],
            'password': generate_password_hash(request.form['password'])
        }
        if supabase.table('users').select('id').eq('username', u['username']).execute().data:
            flash('El usuario ya existe', 'warning')
            return redirect(url_for('admin_usuario_nuevo'))
        supabase.table('users').insert(u).execute()
        flash('Usuario creado correctamente', 'success')
        return redirect(url_for('admin_usuarios'))
    return render_template('admin/usuario_form.html', accion='Nuevo')

@app.route('/admin/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_usuario_editar(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    resp = supabase.table('users').select('*').eq('id', user_id).execute()
    u = resp.data[0] if resp.data else {}
    if request.method == 'POST':
        upd = {
            'username': request.form['username'],
            'nombre': request.form['nombre'],
            'email': request.form['email'],
            'role': request.form['role']
        }
        if request.form.get('password'):
            upd['password'] = generate_password_hash(request.form['password'])
        supabase.table('users').update(upd).eq('id', user_id).execute()
        flash('Usuario actualizado correctamente', 'success')
        return redirect(url_for('admin_usuarios'))
    return render_template('admin/usuario_form.html', accion='Editar', user=u)

@app.route('/admin/usuarios/eliminar/<int:user_id>', methods=['POST'])
@login_required
def admin_usuario_eliminar(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    supabase.table('users').delete().eq('id', user_id).execute()
    flash('Usuario eliminado', 'success')
    return redirect(url_for('admin_usuarios'))

# Reportes y exportación
@app.route('/reportes', methods=['GET', 'POST'])
@login_required
def reportes():
    if current_user.role not in ['admin', 'tecnico']:
        return redirect(url_for('login'))
    q = supabase.table('solicitud').select('*')
    estado = request.form.get('estado', 'Todos')
    if estado != 'Todos':
        q = q.eq('estado', estado)
    fi, ff = request.form.get('fecha_inicio'), request.form.get('fecha_fin')
    if fi: q = q.gte('fecha_creacion', fi)
    if ff: q = q.lte('fecha_creacion', ff)
    data = q.execute().data or []
    
    # Convertir fechas de strings a objetos datetime
    for s in data:
        if 'fecha_creacion' in s and isinstance(s['fecha_creacion'], str):
            s['fecha_creacion'] = datetime.fromisoformat(s['fecha_creacion'])
        if 'fecha_finalizacion' in s and isinstance(s['fecha_finalizacion'], str):
            s['fecha_finalizacion'] = datetime.fromisoformat(s['fecha_finalizacion']) if s['fecha_finalizacion'] else None
            
    return render_template('reportes.html', solicitudes=data)

@app.route('/reportes/exportar_excel', methods=['POST'])
@login_required
def exportar_excel():
    if current_user.role not in ['admin', 'tecnico']:
        return redirect(url_for('login'))
    q = supabase.table('solicitud').select('*')
    estado = request.form.get('estado', 'Todos')
    if estado != 'Todos':
        q = q.eq('estado', estado)
    fi, ff = request.form.get('fecha_inicio'), request.form.get('fecha_fin')
    if fi: q = q.gte('fecha_creacion', fi)
    if ff: q = q.lte('fecha_creacion', ff)
    datos = q.execute().data or []
    df = pd.DataFrame(datos)
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    buf.seek(0)
    fn = f"reportes_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(buf, as_attachment=True, download_name=fn,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# Verificar usuario (AJAX)
@app.route('/verificar_usuario')
def verificar_usuario():
    username = request.args.get('username')
    exists = bool(supabase.table('users').select('id').eq('username', username).execute().data)
    return jsonify({'exists': exists})

# Socket.IO handlers
@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        emit('usuario_conectado', {'id': current_user.id, 'rol': current_user.role})

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        emit('usuario_desconectado', {'id': current_user.id, 'rol': current_user.role})

# Crear usuario admin por defecto
with app.app_context():
    res = supabase.table("users").select("id").eq("username", "admin").execute()
    if not res.data:
        supabase.table("users").insert({
            "username": "admin",
            "password": generate_password_hash("admin123"),
            "nombre": "Administrador del Sistema",
            "email": "christopher.burdiles@araucanianorte.cl",
            "role": "admin"
        }).execute()
        print("✅ Usuario admin creado con éxito.")
    else:
        print("ℹ️ Usuario admin ya existe.")

# Punto de arranque (para desarrollo local)
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
