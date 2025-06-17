import os
from app import db

# 1. Asegurarse de que exista la carpeta 'instance/'
instance_path = os.path.join(os.path.dirname(__file__), 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)
    print("[✔] Carpeta 'instance/' creada.")
else:
    print("[✓] Carpeta 'instance/' ya existe.")

# 2. Crear las tablas en la base de datos
with db.engine.connect():  # garantiza que el engine esté listo
    db.create_all()
print("[✔] Base de datos creada correctamente en 'instance/mantenimiento.db'.")
from werkzeug.security import generate_password_hash
from app import db, User

# Sólo si aún no existe:
if not User.query.filter_by(username='admin').first():
    admin = User(
        username='admin',
        password=generate_password_hash('admin123'),
        role='user',          # o 'tecnico' si prefieres
        nombre='Administrador',
        email='admin@tudominio.com'
    )
    db.session.add(admin)
    db.session.commit()
    print("Usuario 'admin' creado con contraseña 'admin123'")