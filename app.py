from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
from base64 import b64decode
import uuid
from flask import jsonify
import io
import pandas as pd
from flask import send_file
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

def notificar_tecnicos_y_admins(mensaje, tipo='info'):
    socketio.emit('nueva_notificacion', {
        'mensaje': mensaje,
        'tipo': tipo,
        'timestamp': datetime.utcnow().isoformat()
    })


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Inicializar Supabase
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_KEY')
)

socketio = SocketIO(app)

# Setup de Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Modelo de Usuario
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
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        if response.data:
            user_data = response.data[0]
            return User(
                id=user_data['id'],
                username=user_data['username'],
                password=user_data['password'],
                role=user_data['role'],
                nombre=user_data['nombre'],
                email=user_data['email']
            )
        return None

    @staticmethod
    def get_by_username(username):
        response = supabase.table('users').select('*').eq('username', username).execute()
        if response.data:
            user_data = response.data[0]
            return User(
                id=user_data['id'],
                username=user_data['username'],
                password=user_data['password'],
                role=user_data['role'],
                nombre=user_data['nombre'],
                email=user_data['email']
            )
        return None

asignaciones_tecnicos = db.Table('asignaciones_tecnicos',
    db.Column('solicitud_id', db.Integer, db.ForeignKey('solicitud.id')),
    db.Column('tecnico_id', db.Integer, db.ForeignKey('user.id'))
)

class Solicitud(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo_trabajo = db.Column(db.String(64), nullable=False)
    tipo_actividad = db.Column(db.String(64), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    ubicacion = db.Column(db.String(128), nullable=False)
    prioridad = db.Column(db.String(10), nullable=False)
    foto = db.Column(db.String(128))
    estado = db.Column(db.String(32), default='Pendiente')
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_inicio = db.Column(db.DateTime)
    fecha_finalizacion = db.Column(db.DateTime)
    tecnicos_asignados = db.relationship('User', secondary=asignaciones_tecnicos, backref='solicitudes_asignadas')
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    firma = db.Column(db.String(128))
 

    usuario = db.relationship('User', foreign_keys=[usuario_id])

    def calcular_tiempo_total(self):
        if self.fecha_inicio and self.fecha_finalizacion:
            return (self.fecha_finalizacion - self.fecha_inicio).total_seconds() / 60
        return None

    def esta_atrasada(self):
        if self.tiempo_estimado and self.fecha_inicio:
            tiempo_transcurrido = (datetime.utcnow() - self.fecha_inicio).total_seconds() / 60
            return tiempo_transcurrido > self.tiempo_estimado
        return False

class Comentario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contenido = db.Column(db.Text, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    solicitud_id = db.Column(db.Integer, db.ForeignKey('solicitud.id'))
    usuario = db.relationship('User', backref='comentarios')

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Crear tablas
with app.app_context():
    db.create_all()

# Rutas de autenticación
@app.route('/')
def index():
    return redirect(url_for('login'))

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
            return redirect(url_for('user_dashboard'))
        flash('Usuario o contraseña incorrectos', 'danger')
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        nombre = request.form['nombre']
        email = request.form['email']
        role = request.form['role']

        # Verificar si el usuario ya existe
        existing_user = User.get_by_username(username)
        if existing_user:
            flash('El nombre de usuario ya existe', 'danger')
            return redirect(url_for('register'))

        # Crear nuevo usuario en Supabase
        new_user = {
            'username': username,
            'password': password,
            'nombre': nombre,
            'email': email,
            'role': role
        }
        response = supabase.table('users').insert(new_user).execute()
        
        flash('Registro exitoso. Por favor inicie sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')

# Rutas Admin
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Acceso restringido solo para administradores.', 'danger')
        return redirect(url_for('login'))

    solicitudes = Solicitud.query.order_by(Solicitud.fecha_creacion.desc()).all()
    return render_template('admin/dashboard.html', solicitudes=solicitudes)

@app.route('/admin/asignar_tecnicos/<int:solicitud_id>', methods=['GET', 'POST'])
@login_required
def asignar_tecnicos(solicitud_id):
    if current_user.role != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))

    solicitud = Solicitud.query.get_or_404(solicitud_id)
    tecnicos = User.query.filter_by(role='tecnico').all()

    if request.method == 'POST':
        seleccionados = request.form.getlist('tecnicos')
        solicitud.tecnicos_asignados = [User.query.get(int(id)) for id in seleccionados]
        db.session.commit()

        # Notificar a los técnicos asignados
        for tecnico in solicitud.tecnicos_asignados:
            mensaje = f"Nueva solicitud asignada: #{solicitud.id} - {solicitud.tipo_trabajo}"
            socketio.emit('nueva_asignacion', {
                'tecnico_id': tecnico.id,
                'mensaje': mensaje,
                'tipo': 'asignacion',
                'timestamp': datetime.utcnow().isoformat()
            })

        flash('Técnicos asignados correctamente.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/asignar_tecnicos.html', solicitud=solicitud, tecnicos=tecnicos)

@app.route('/admin/solicitud/eliminar/<int:solicitud_id>', methods=['POST'])
@login_required
def eliminar_solicitud(solicitud_id):
    if current_user.role != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))
    
    solicitud = Solicitud.query.get_or_404(solicitud_id)
    
    # Eliminar archivos asociados si existen
    if solicitud.foto:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], solicitud.foto))
        except:
            pass
    if solicitud.firma:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], solicitud.firma))
        except:
            pass
    
    db.session.delete(solicitud)
    db.session.commit()
    flash('Solicitud eliminada correctamente.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/solicitud/editar/<int:solicitud_id>', methods=['GET', 'POST'])
@login_required
def editar_solicitud(solicitud_id):
    if current_user.role != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))
    
    solicitud = Solicitud.query.get_or_404(solicitud_id)
    
    if request.method == 'POST':
        solicitud.tipo_trabajo = request.form['tipo_trabajo']
        solicitud.tipo_actividad = request.form['tipo_actividad']
        solicitud.descripcion = request.form['descripcion']
        solicitud.ubicacion = request.form['ubicacion']
        solicitud.prioridad = request.form['prioridad']
        solicitud.estado = request.form['estado']
        
        # Manejar nueva foto si se sube una
        foto = request.files.get('foto')
        if foto and foto.filename:
            # Eliminar foto anterior si existe
            if solicitud.foto:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], solicitud.foto))
                except:
                    pass
            
            filename = secure_filename(foto.filename)
            ruta_foto = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            foto.save(ruta_foto)
            solicitud.foto = filename
        
        db.session.commit()
        flash('Solicitud actualizada correctamente.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/editar_solicitud.html', solicitud=solicitud)

# Listar todos los usuarios
@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if current_user.role != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))
    usuarios = User.query.order_by(User.role, User.nombre).all()
    return render_template('admin/usuarios.html', usuarios=usuarios)

# Crear nuevo usuario/técnico
@app.route('/admin/usuarios/nuevo', methods=['GET', 'POST'])
@login_required
def admin_usuario_nuevo():
    if current_user.role != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        nombre   = request.form['nombre']
        email    = request.form['email']
        role     = request.form['role']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            flash('El usuario ya existe.', 'warning')
            return redirect(url_for('admin_usuario_nuevo'))
        nuevo = User(username=username, nombre=nombre, email=email, role=role, password=password)
        db.session.add(nuevo)
        db.session.commit()
        flash('Usuario creado correctamente.', 'success')
        return redirect(url_for('admin_usuarios'))
    return render_template('admin/usuario_form.html', accion='Nuevo')

# Editar usuario/técnico
@app.route('/admin/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_usuario_editar(user_id):
    if current_user.role != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.nombre   = request.form['nombre']
        user.email    = request.form['email']
        user.role     = request.form['role']
        pwd = request.form.get('password')
        if pwd:
            user.password = generate_password_hash(pwd)
        db.session.commit()
        flash('Usuario actualizado correctamente.', 'success')
        return redirect(url_for('admin_usuarios'))
    return render_template('admin/usuario_form.html', accion='Editar', user=user)

# Eliminar usuario/técnico
@app.route('/admin/usuarios/eliminar/<int:user_id>', methods=['POST'])
@login_required
def admin_usuario_eliminar(user_id):
    if current_user.role != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Usuario eliminado.', 'success')
    return redirect(url_for('admin_usuarios'))

# Rutas de usuario
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('login'))
    solicitudes = Solicitud.query.filter_by(usuario_id=current_user.id).all()
    return render_template('user/dashboard.html', solicitudes=solicitudes)

# Ruta de nueva solicitud
@app.route('/user/solicitud', methods=['GET', 'POST'])
@login_required
def nueva_solicitud():
    if request.method == 'POST':
        try:
            # Validar campos requeridos
            campos_requeridos = ['tipo_trabajo', 'tipo_actividad', 'descripcion', 'ubicacion', 'prioridad']
            for campo in campos_requeridos:
                if not request.form.get(campo):
                    flash(f'El campo {campo} es requerido', 'danger')
                    return redirect(url_for('nueva_solicitud'))

            # Validar descripción
            descripcion = request.form['descripcion']
            if len(descripcion) < 20:
                flash('La descripción debe tener al menos 20 caracteres', 'danger')
                return redirect(url_for('nueva_solicitud'))

            # Procesar archivos
            fotos = request.files.getlist('foto')
            filenames = []
            for foto in fotos[:3]:  # Limitar a 3 fotos
                if foto and foto.filename:
                    # Validar tipo de archivo
                    if not foto.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                        flash('Solo se permiten archivos de imagen (PNG, JPG, GIF)', 'danger')
                        return redirect(url_for('nueva_solicitud'))
                    
                    # Validar tamaño (5MB máximo)
                    if len(foto.read()) > 5 * 1024 * 1024:
                        flash('Las imágenes no deben superar los 5MB', 'danger')
                        return redirect(url_for('nueva_solicitud'))
                    foto.seek(0)  # Resetear el puntero del archivo
                    
                    filename = secure_filename(foto.filename)
                    ruta_foto = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    foto.save(ruta_foto)
                    filenames.append(filename)

            # Crear nueva solicitud
            nueva = Solicitud(
                tipo_trabajo=request.form['tipo_trabajo'],
                tipo_actividad=request.form['tipo_actividad'],
                descripcion=descripcion,
                ubicacion=request.form['ubicacion'],
                prioridad=request.form['prioridad'],
                foto=','.join(filenames) if filenames else None,
                usuario_id=current_user.id,
                tiempo_estimado=int(float(request.form.get('tiempo_estimado', 0)) * 60) if request.form.get('tiempo_estimado') else None,
                costo_estimado=float(request.form.get('costo_estimado', 0)) if request.form.get('costo_estimado') else None
            )

            db.session.add(nueva)
            db.session.commit()

            # Notificar a técnicos y admins
            mensaje = f"Nueva solicitud #{nueva.id} creada: {nueva.tipo_trabajo} - {nueva.tipo_actividad}"
            notificar_tecnicos_y_admins(mensaje, 'nueva_solicitud')

            flash('Solicitud enviada correctamente.', 'success')
            return redirect(url_for('user_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error al crear la solicitud: {str(e)}', 'danger')
            return redirect(url_for('nueva_solicitud'))

    return render_template('user/solicitud.html')

# Rutas de técnico

@app.route('/tecnico/dashboard')
@login_required
def tecnico_dashboard():
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))

    solicitudes = Solicitud.query.filter(Solicitud.tecnicos_asignados.any(id=current_user.id)).order_by(Solicitud.fecha_creacion.desc()).all()
    return render_template('tecnico/dashboard.html', solicitudes=solicitudes)

#Ruta de Repostes

@app.route('/reportes', methods=['GET', 'POST'])
@login_required
def reportes():
    if current_user.role not in ['tecnico', 'admin']:
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))

    # Leer filtros
    estado       = request.form.get('estado', 'Todos')
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin    = request.form.get('fecha_fin')

    # Construir la query
    query = Solicitud.query
    if estado != 'Todos':
        query = query.filter(Solicitud.estado == estado)
    if fecha_inicio:
        query = query.filter(Solicitud.fecha_creacion >= fecha_inicio)
    if fecha_fin:
        query = query.filter(Solicitud.fecha_creacion <= fecha_fin)

    solicitudes = query.order_by(Solicitud.fecha_creacion.desc()).all()

 # Datos para gráficos
    from sqlalchemy import func
    agrupado = db.session.query(
        Solicitud.tipo_actividad,
        func.count(Solicitud.id)
    ).group_by(Solicitud.tipo_actividad).all()

    etiquetas = [tipo for tipo, _ in agrupado]
    totales   = [total for _, total in agrupado]

    # Si es JSON (AJAX), devolvemos solo datos para JS
    if request.is_json:
        return jsonify(
            solicitudes=[{
                'id': s.id,
                'usuario': s.usuario.nombre,
                'tipo_trabajo': s.tipo_trabajo,
                'tipo_actividad': s.tipo_actividad,
                'estado': s.estado,
                'fecha_creacion': s.fecha_creacion.strftime('%d-%m-%Y'),
                'fecha_finalizacion': s.fecha_finalizacion.strftime('%d-%m-%Y') if s.fecha_finalizacion else '-'
            } for s in solicitudes],
            etiquetas=etiquetas,
            totales=totales
        )

    # Sino, render normal
    filtros = {
        'estado': estado,
        'fecha_inicio': fecha_inicio or '',
        'fecha_fin': fecha_fin or ''
    }
    return render_template('reportes.html',
                           solicitudes=solicitudes,
                           filtros=filtros,
                           etiquetas=etiquetas,
                           totales=totales)

@app.route('/reportes/exportar_excel', methods=['POST'])
@login_required
def exportar_excel():
    if current_user.role not in ['tecnico', 'admin']:
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('reportes'))

    # Leer filtros del formulario
    estado       = request.form.get('estado', 'Todos')
    fecha_inicio = request.form.get('fecha_inicio')
    fecha_fin    = request.form.get('fecha_fin')

    # Query idéntica a la de reportes()
    query = Solicitud.query
    if estado != 'Todos':
        query = query.filter(Solicitud.estado == estado)
    if fecha_inicio:
        query = query.filter(Solicitud.fecha_creacion >= fecha_inicio)
    if fecha_fin:
        query = query.filter(Solicitud.fecha_creacion <= fecha_fin)
    datos = query.order_by(Solicitud.fecha_creacion.desc()).all()

    # Construir DataFrame
    df = pd.DataFrame([{
        'ID': s.id,
        'Usuario': s.usuario.nombre,
        'Trabajo': s.tipo_trabajo,
        'Actividad': s.tipo_actividad,
        'Estado': s.estado,
        'Creación': s.fecha_creacion.strftime('%d-%m-%Y'),
        'Finalización': s.fecha_finalizacion.strftime('%d-%m-%Y') if s.fecha_finalizacion else ''
    } for s in datos])

    # Escribir a Excel en memoria
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Reportes')
    output.seek(0)

    # Devolver como attachment
    filename = f"reportes_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


@app.route('/tecnico/orden/<int:id>', methods=['GET', 'POST'])
@login_required
def gestion_orden(id):
    if current_user.role != 'tecnico':
        return redirect(url_for('login'))

    solicitud = Solicitud.query.get_or_404(id)

    if request.method == 'POST':
        estado_anterior = solicitud.estado
        solicitud.estado = request.form['estado']
        solicitud.fecha_finalizacion = datetime.utcnow()
        solicitud.tecnico_asignado_id = current_user.id

        # Subida de imagen de evidencia
        evidencia = request.files.get('evidencia')
        if evidencia and evidencia.filename:
            filename = f"evidencia_{uuid.uuid4().hex}_{secure_filename(evidencia.filename)}"
            ruta_foto = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            evidencia.save(ruta_foto)
            solicitud.foto = filename

        # Captura de firma en base64
        firma_data = request.form.get('firma')
        if firma_data and firma_data.startswith("data:image/png;base64,"):
            firma_b64 = firma_data.split(",")[1]
            firma_bin = b64decode(firma_b64)
            firma_filename = f"firma_{uuid.uuid4().hex}.png"
            ruta_firma = os.path.join(app.config['UPLOAD_FOLDER'], firma_filename)
            with open(ruta_firma, "wb") as f:
                f.write(firma_bin)
            solicitud.firma = firma_filename

        db.session.commit()

        # Notificar al usuario sobre el cambio de estado
        if estado_anterior != solicitud.estado:
            mensaje = f"La solicitud #{solicitud.id} ha cambiado de estado a: {solicitud.estado}"
            notificar_tecnicos_y_admins(mensaje, 'estado')

        flash('Solicitud actualizada correctamente.', 'success')
        return redirect(url_for('tecnico_dashboard'))

    return render_template('tecnico/orden.html', solicitud=solicitud)

@app.route('/verificar_usuario')
def verificar_usuario():
    username = request.args.get('username')
    exists = User.query.filter_by(username=username).first() is not None
    return {'exists': exists}

# Socket.IO
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        if current_user.role == 'tecnico':
            emit('tecnico_connected', {'user_id': current_user.id})
        elif current_user.role == 'admin':
            emit('admin_connected', {'user_id': current_user.id})

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        if current_user.role == 'tecnico':
            emit('tecnico_disconnected', {'user_id': current_user.id})
        elif current_user.role == 'admin':
            emit('admin_disconnected', {'user_id': current_user.id})

with app.app_context():
    from werkzeug.security import generate_password_hash

    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),  # puedes cambiar la contraseña
            nombre='Administrador del Sistema',
            email='admin@hospital.cl',
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Usuario admin creado con éxito.")
    else:
        print("ℹ️ Usuario admin ya existe.")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
