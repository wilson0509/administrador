from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pymysql
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuración
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Conexión a la base de datos
def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        database='sistema_gestion',
        cursorclass=pymysql.cursors.DictCursor,
        charset='utf8mb4'
    )

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SHOW COLUMNS FROM usuario LIKE 'password'")
            result = cursor.fetchone()
            if not result:
                cursor.execute("ALTER TABLE usuario ADD COLUMN password VARCHAR(255) NOT NULL AFTER Telefono")
                cursor.execute("UPDATE usuario SET password = 'admin123' WHERE Tipo_usuario = 'Administrador'")
                cursor.execute("UPDATE usuario SET password = 'aprendiz123' WHERE Tipo_usuario = 'Aprendiz'")
                cursor.execute("UPDATE usuario SET password = 'delegado123' WHERE Tipo_usuario = 'Delegado'")
                conn.commit()
    finally:
        conn.close()

# Filtro personalizado para verificar tareas atrasadas
@app.template_filter('esta_atrasada')
def esta_atrasada(fecha_finalizacion, estado_tarea):
    if fecha_finalizacion and estado_tarea == 'Pendiente':
        return fecha_finalizacion < datetime.now().date()
    return False

# Rutas principales
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM usuario WHERE Email = %s', (email,))
                user = cursor.fetchone()
                
                if user and user['password'] == password:  # En producción usar check_password_hash
                    session['user_id'] = user['Id_Usuario']
                    session['user_name'] = f"{user['Nombres']} {user['Apellidos']}"
                    session['user_type'] = user['Tipo_usuario']
                    flash('Inicio de sesión exitoso', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Credenciales incorrectas', 'danger')
        except Exception as e:
            print(f"Error en login: {e}")
            flash('Error al procesar la solicitud', 'danger')
        finally:
            conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión correctamente', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_type = session.get('user_type')
    stats = {}
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if user_type == 'Administrador':
                cursor.execute('SELECT COUNT(*) as total FROM usuario')
                stats['usuarios'] = cursor.fetchone()['total']
                
                cursor.execute('SELECT COUNT(*) as total FROM documento_digital')
                stats['documentos'] = cursor.fetchone()['total']
                
                cursor.execute('SELECT COUNT(*) as total FROM alerta_sistema')
                stats['alertas'] = cursor.fetchone()['total']
                
            elif user_type == 'Aprendiz':
                cursor.execute('SELECT COUNT(*) as total FROM solicitud_permiso WHERE Aprendiz_Usuario_Id_Usuario = %s', 
                              (session['user_id'],))
                stats['permisos'] = cursor.fetchone()['total']
                
                cursor.execute('''SELECT COUNT(*) as total FROM tareas_dirigidas 
                                WHERE Aprendiz_Usuario_Id_Usuario = %s AND estado_tarea = "Pendiente"''', 
                              (session['user_id'],))
                stats['tareas_pendientes'] = cursor.fetchone()['total']
                
            elif user_type == 'Delegado':
                cursor.execute('''SELECT COUNT(*) as total FROM delegado_has_alerta_sistema 
                                WHERE Delegado_Usuario_Id_Usuario = %s''', 
                              (session['user_id'],))
                stats['alertas_asignadas'] = cursor.fetchone()['total']
    finally:
        conn.close()
    
    return render_template('dashboard.html', stats=stats, user_type=user_type)

# Rutas de permisos
@app.route('/permisos', methods=['GET', 'POST'])
def permisos():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_type = session.get('user_type')
    
    if request.method == 'POST' and user_type == 'Aprendiz':
        motivo = request.form['motivo']
        urgencia = request.form['urgencia']
        evidencia_tipo = request.form['evidencia_tipo']
        evidencia_valor = request.form['evidencia_valor']
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT Id_Aprendiz FROM aprendiz WHERE Usuario_Id_Usuario = %s', 
                              (session['user_id'],))
                aprendiz = cursor.fetchone()
                
                if aprendiz:
                    cursor.execute('''
                        INSERT INTO solicitud_permiso 
                        (motivo, urgencia, evidencia_tipo, evidencia_valor, estado_permiso, 
                         Aprendiz_Id_Aprendiz, Aprendiz_Usuario_Id_Usuario)
                        VALUES (%s, %s, %s, %s, 'Pendiente', %s, %s)
                    ''', (motivo, urgencia, evidencia_tipo, evidencia_valor, 
                          aprendiz['Id_Aprendiz'], session['user_id']))
                    conn.commit()
                    flash('Solicitud de permiso enviada correctamente', 'success')
        except Exception as e:
            print(f"Error al crear permiso: {e}")
            flash('Error al enviar la solicitud', 'danger')
        finally:
            conn.close()
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if user_type in ['Administrador', 'Delegado']:
                cursor.execute('''
                    SELECT sp.*, u.Nombres, u.Apellidos 
                    FROM solicitud_permiso sp
                    JOIN usuario u ON sp.Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                    ORDER BY sp.fecha_solicitud DESC
                ''')
                permisos = cursor.fetchall()
            elif user_type == 'Aprendiz':
                cursor.execute('''
                    SELECT sp.* 
                    FROM solicitud_permiso sp
                    WHERE sp.Aprendiz_Usuario_Id_Usuario = %s
                    ORDER BY sp.fecha_solicitud DESC
                ''', (session['user_id'],))
                permisos = cursor.fetchall()
            else:
                permisos = []
    finally:
        conn.close()
    
    return render_template('permisos.html', permisos=permisos, user_type=user_type)

@app.route('/permisos/accion/<int:id>', methods=['POST'])
def accion_permiso(id):
    if 'user_id' not in session or session.get('user_type') not in ['Administrador', 'Delegado']:
        return redirect(url_for('login'))
    
    accion = request.form['accion']
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if accion in ['Aprobado', 'Rechazado']:
                cursor.execute('''
                    UPDATE solicitud_permiso 
                    SET estado_permiso = %s, fecha_respuesta = NOW() 
                    WHERE Id_Solicitud_Permiso = %s
                ''', (accion, id))
                
                if accion == 'Rechazado':
                    cursor.execute('''
                        INSERT INTO alerta_sistema 
                        (tipo_alerta, descripcion, nivel_urgencia, estado_alerta, 
                         Solicitud_Permiso_Id_Solicitud_Permiso, Solicitud_Permiso_Aprendiz_Id_Aprendiz, 
                         Solicitud_Permiso_Aprendiz_Usuario_Id_Usuario)
                        SELECT 
                            'Permiso Rechazado', 
                            CONCAT('Solicitud de permiso rechazada: ', motivo), 
                            'Medio', 
                            'Nueva',
                            Id_Solicitud_Permiso, 
                            Aprendiz_Id_Aprendiz, 
                            Aprendiz_Usuario_Id_Usuario
                        FROM solicitud_permiso 
                        WHERE Id_Solicitud_Permiso = %s
                    ''', (id,))
                
                conn.commit()
                flash(f'Permiso {accion.lower()} correctamente', 'success')
    except Exception as e:
        print(f"Error al procesar permiso: {e}")
        flash('Error al procesar la solicitud', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('permisos'))

# Rutas de alertas
@app.route('/alertas')
def alertas():
    if 'user_id' not in session or session.get('user_type') not in ['Administrador', 'Delegado']:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if session.get('user_type') == 'Delegado':
                cursor.execute('''
                    SELECT a.*, u.Nombres, u.Apellidos 
                    FROM alerta_sistema a
                    JOIN delegado_has_alerta_sistema dha ON a.Id_Alerta_sistema = dha.Alerta_sistema_Id_Alerta_sistema
                    LEFT JOIN usuario u ON a.Solicitud_Permiso_Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                    WHERE dha.Delegado_Usuario_Id_Usuario = %s
                    ORDER BY a.fecha_generacion DESC
                ''', (session['user_id'],))
            else:
                cursor.execute('''
                    SELECT a.*, u.Nombres, u.Apellidos 
                    FROM alerta_sistema a
                    LEFT JOIN usuario u ON a.Solicitud_Permiso_Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                    ORDER BY a.fecha_generacion DESC
                ''')
            
            alertas = cursor.fetchall()
    finally:
        conn.close()
    
    return render_template('alertas.html', alertas=alertas)

@app.route('/alertas/accion/<int:id>', methods=['POST'])
def accion_alerta(id):
    if 'user_id' not in session or session.get('user_type') not in ['Administrador', 'Delegado']:
        return redirect(url_for('login'))
    
    accion = request.form['accion']
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                UPDATE alerta_sistema 
                SET estado_alerta = %s 
                WHERE Id_Alerta_sistema = %s
            ''', (accion, id))
            conn.commit()
            flash(f'Alerta marcada como {accion.lower()}', 'success')
    except Exception as e:
        print(f"Error al actualizar alerta: {e}")
        flash('Error al procesar la alerta', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('alertas'))

# Rutas de tareas
@app.route('/tareas')
def tareas():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_type = session.get('user_type')
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if user_type == 'Administrador':
                cursor.execute('''
                    SELECT t.*, u.Nombres, u.Apellidos 
                    FROM tareas_dirigidas t
                    JOIN usuario u ON t.Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                    ORDER BY t.fecha_asignacion DESC
                ''')
                tareas = cursor.fetchall()
                
                cursor.execute('SELECT Id_Aprendiz, Usuario_Id_Usuario FROM aprendiz')
                aprendices = cursor.fetchall()
            elif user_type == 'Aprendiz':
                cursor.execute('''
                    SELECT t.* 
                    FROM tareas_dirigidas t
                    WHERE t.Aprendiz_Usuario_Id_Usuario = %s
                    ORDER BY t.fecha_asignacion DESC
                ''', (session['user_id'],))
                tareas = cursor.fetchall()
                aprendices = []
            else:
                tareas = []
                aprendices = []
    finally:
        conn.close()
    
    return render_template('tareas.html', 
                         tareas=tareas, 
                         aprendices=aprendices, 
                         user_type=user_type)

@app.route('/tareas/nueva', methods=['POST'])
def nueva_tarea():
    if 'user_id' not in session or session.get('user_type') != 'Administrador':
        return redirect(url_for('login'))
    
    descripcion = request.form['descripcion']
    fecha_finalizacion = request.form['fecha_finalizacion']
    aprendiz_id = request.form['aprendiz_id']
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                INSERT INTO tareas_dirigidas 
                (descripcion, fecha_asignacion, fecha_finalizacion, estado_tarea, 
                 Aprendiz_Id_Aprendiz, Aprendiz_Usuario_Id_Usuario, 
                 Administrador_Id_Administrador, Administrador_Usuario_Id_Usuario)
                SELECT 
                    %s, NOW(), %s, 'Pendiente',
                    a.Id_Aprendiz, a.Usuario_Id_Usuario,
                    ad.Id_Administrador, ad.Usuario_Id_Usuario
                FROM aprendiz a
                JOIN administrador ad ON ad.Usuario_Id_Usuario = %s
                WHERE a.Id_Aprendiz = %s
            ''', (descripcion, fecha_finalizacion, session['user_id'], aprendiz_id))
            conn.commit()
            flash('Tarea asignada correctamente', 'success')
    except Exception as e:
        print(f"Error al crear tarea: {e}")
        flash('Error al asignar la tarea', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('tareas'))

@app.route('/tareas/estado/<int:id>', methods=['POST'])
def cambiar_estado_tarea(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    nuevo_estado = request.form['estado']
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                UPDATE tareas_dirigidas 
                SET estado_tarea = %s 
                WHERE Id_Tareas_dirigidas = %s AND Aprendiz_Usuario_Id_Usuario = %s
            ''', (nuevo_estado, id, session['user_id']))
            conn.commit()
            flash('Estado de la tarea actualizado', 'success')
    except Exception as e:
        print(f"Error al actualizar tarea: {e}")
        flash('Error al actualizar la tarea', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('tareas'))

# Rutas de comida
@app.route('/comida')
def comida():
    if 'user_id' not in session or session.get('user_type') != 'Administrador':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT e.*, u.Nombres, u.Apellidos 
                FROM entrega_comida e
                JOIN usuario u ON e.Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                ORDER BY e.fecha_entrega DESC
            ''')
            entregas = cursor.fetchall()
            
            cursor.execute('SELECT * FROM reporte_corsamo')
            reportes = cursor.fetchall()
    finally:
        conn.close()
    
    return render_template('comida.html', entregas=entregas, reportes=reportes)

@app.route('/comida/estado/<int:id>', methods=['POST'])
def cambiar_estado_comida(id):
    if 'user_id' not in session or session.get('user_type') != 'Administrador':
        return redirect(url_for('login'))
    
    nuevo_estado = request.form['estado']
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                UPDATE entrega_comida 
                SET estado_entrega = %s 
                WHERE Id_Entrega_comida = %s
            ''', (nuevo_estado, id))
            conn.commit()
            flash('Estado de entrega actualizado', 'success')
    except Exception as e:
        print(f"Error al actualizar entrega: {e}")
        flash('Error al actualizar la entrega', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('comida'))

# Rutas de documentos
@app.route('/documentos')
def documentos():
    if 'user_id' not in session or session.get('user_type') != 'Administrador':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT d.*, u.Nombres, u.Apellidos 
                FROM documento_digital d
                JOIN usuario u ON d.Administrador_Usuario_Id_Usuario = u.Id_Usuario
                ORDER BY d.fecha_subida DESC
            ''')
            documentos = cursor.fetchall()
    finally:
        conn.close()
    
    return render_template('documentos.html', documentos=documentos)

@app.route('/documentos/subir', methods=['POST'])
def subir_documento():
    if 'user_id' not in session or session.get('user_type') != 'Administrador':
        return redirect(url_for('login'))
    
    nombre = request.form['nombre']
    tipo = request.form['tipo']
    archivo = request.files['archivo']
    
    if archivo and allowed_file(archivo.filename):
        filename = secure_filename(archivo.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        archivo.save(filepath)
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('''
                    INSERT INTO documento_digital 
                    (nombre_documento, tipo_documento, archivo_pdf, fecha_subida, usuario_subio, 
                     Administrador_Id_Administrador, Administrador_Usuario_Id_Usuario)
                    SELECT 
                        %s, %s, %s, NOW(), CONCAT(u.Nombres, ' ', u.Apellidos),
                        a.Id_Administrador, a.Usuario_Id_Usuario
                    FROM administrador a
                    JOIN usuario u ON a.Usuario_Id_Usuario = u.Id_Usuario
                    WHERE a.Usuario_Id_Usuario = %s
                ''', (nombre, tipo, filename, session['user_id']))
                conn.commit()
                flash('Documento subido correctamente', 'success')
        except Exception as e:
            print(f"Error al subir documento: {e}")
            flash('Error al subir el documento', 'danger')
        finally:
            conn.close()
    else:
        flash('Solo se permiten archivos PDF', 'danger')
    
    return redirect(url_for('documentos'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)