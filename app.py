from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pymysql
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps

app = Flask(__name__)
api = Api(app)

# Configuración
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

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

# Decorador para verificar roles
def role_required(roles):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute('SELECT Tipo_usuario FROM usuario WHERE Id_Usuario = %s', (current_user_id,))
                    user = cursor.fetchone()
                    if not user or user['Tipo_usuario'] not in roles:
                        return {'message': 'Acceso no autorizado'}, 403
            finally:
                conn.close()
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Clases de recursos
class Login(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM usuario WHERE Email = %s', (email,))
                user = cursor.fetchone()
                
                if user and user['password'] == password:  # En producción usar check_password_hash
                    access_token = create_access_token(identity=user['Id_Usuario'])
                    return {
                        'access_token': access_token,
                        'user_id': user['Id_Usuario'],
                        'user_type': user['Tipo_usuario']
                    }, 200
                else:
                    return {'message': 'Credenciales inválidas'}, 401
        except Exception as e:
            return {'message': str(e)}, 500
        finally:
            conn.close()

class Usuario(Resource):
    @jwt_required()
    def get(self, user_id):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM usuario WHERE Id_Usuario = %s', (user_id,))
                user = cursor.fetchone()
                if user:
                    return jsonify(user)
                return {'message': 'Usuario no encontrado'}, 404
        finally:
            conn.close()

class PermisoList(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Verificar tipo de usuario
                cursor.execute('SELECT Tipo_usuario FROM usuario WHERE Id_Usuario = %s', (user_id,))
                user = cursor.fetchone()
                
                if user['Tipo_usuario'] == 'Aprendiz':
                    cursor.execute('''
                        SELECT sp.* 
                        FROM solicitud_permiso sp
                        WHERE sp.Aprendiz_Usuario_Id_Usuario = %s
                        ORDER BY sp.fecha_solicitud DESC
                    ''', (user_id,))
                else:
                    cursor.execute('''
                        SELECT sp.*, u.Nombres, u.Apellidos 
                        FROM solicitud_permiso sp
                        JOIN usuario u ON sp.Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                        ORDER BY sp.fecha_solicitud DESC
                    ''')
                permisos = cursor.fetchall()
                return jsonify(permisos)
        finally:
            conn.close()

    @role_required(['Aprendiz'])
    def post(self):
        data = request.get_json()
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT Id_Aprendiz FROM aprendiz WHERE Usuario_Id_Usuario = %s', (get_jwt_identity(),))
                aprendiz = cursor.fetchone()
                
                if aprendiz:
                    cursor.execute('''
                        INSERT INTO solicitud_permiso 
                        (motivo, urgencia, evidencia_tipo, evidencia_valor, estado_permiso, 
                         Aprendiz_Id_Aprendiz, Aprendiz_Usuario_Id_Usuario)
                        VALUES (%s, %s, %s, %s, 'Pendiente', %s, %s)
                    ''', (data['motivo'], data['urgencia'], data['evidencia_tipo'], 
                          data['evidencia_valor'], aprendiz['Id_Aprendiz'], get_jwt_identity()))
                    conn.commit()
                    return {'message': 'Solicitud creada'}, 201
                return {'message': 'Usuario no es aprendiz'}, 400
        except Exception as e:
            return {'message': str(e)}, 500
        finally:
            conn.close()

class PermisoDetail(Resource):
    @role_required(['Administrador', 'Delegado'])
    def patch(self, permiso_id):
        data = request.get_json()
        accion = data.get('accion')
        
        if accion not in ['Aprobado', 'Rechazado']:
            return {'message': 'Acción no válida'}, 400
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('''
                    UPDATE solicitud_permiso 
                    SET estado_permiso = %s, fecha_respuesta = NOW() 
                    WHERE Id_Solicitud_Permiso = %s
                ''', (accion, permiso_id))
                
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
                    ''', (permiso_id,))
                
                conn.commit()
                return {'message': f'Permiso {accion.lower()}'}, 200
        except Exception as e:
            return {'message': str(e)}, 500
        finally:
            conn.close()

class TareaList(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT Tipo_usuario FROM usuario WHERE Id_Usuario = %s', (user_id,))
                user = cursor.fetchone()
                
                if user['Tipo_usuario'] == 'Administrador':
                    cursor.execute('''
                        SELECT t.*, u.Nombres, u.Apellidos 
                        FROM tareas_dirigidas t
                        JOIN usuario u ON t.Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                        ORDER BY t.fecha_asignacion DESC
                    ''')
                else:
                    cursor.execute('''
                        SELECT t.* 
                        FROM tareas_dirigidas t
                        WHERE t.Aprendiz_Usuario_Id_Usuario = %s
                        ORDER BY t.fecha_asignacion DESC
                    ''', (user_id,))
                tareas = cursor.fetchall()
                
                # Verificar tareas atrasadas
                for tarea in tareas:
                    if tarea['fecha_finalizacion'] and tarea['estado_tarea'] == 'Pendiente':
                        tarea['atrasada'] = tarea['fecha_finalizacion'] < datetime.now().date()
                    else:
                        tarea['atrasada'] = False
                
                return jsonify(tareas)
        finally:
            conn.close()

    @role_required(['Administrador'])
    def post(self):
        data = request.get_json()
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
                ''', (data['descripcion'], data['fecha_finalizacion'], 
                      get_jwt_identity(), data['aprendiz_id']))
                conn.commit()
                return {'message': 'Tarea creada'}, 201
        except Exception as e:
            return {'message': str(e)}, 500
        finally:
            conn.close()

class TareaDetail(Resource):
    @jwt_required()
    def patch(self, tarea_id):
        data = request.get_json()
        nuevo_estado = data.get('estado')
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('''
                    UPDATE tareas_dirigidas 
                    SET estado_tarea = %s 
                    WHERE Id_Tareas_dirigidas = %s AND Aprendiz_Usuario_Id_Usuario = %s
                ''', (nuevo_estado, tarea_id, get_jwt_identity()))
                conn.commit()
                return {'message': 'Estado actualizado'}, 200
        except Exception as e:
            return {'message': str(e)}, 500
        finally:
            conn.close()

class AlertaList(Resource):
    @role_required(['Administrador', 'Delegado'])
    def get(self):
        user_id = get_jwt_identity()
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT Tipo_usuario FROM usuario WHERE Id_Usuario = %s', (user_id,))
                user = cursor.fetchone()
                
                if user['Tipo_usuario'] == 'Delegado':
                    cursor.execute('''
                        SELECT a.*, u.Nombres, u.Apellidos 
                        FROM alerta_sistema a
                        JOIN delegado_has_alerta_sistema dha ON a.Id_Alerta_sistema = dha.Alerta_sistema_Id_Alerta_sistema
                        LEFT JOIN usuario u ON a.Solicitud_Permiso_Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                        WHERE dha.Delegado_Usuario_Id_Usuario = %s
                        ORDER BY a.fecha_generacion DESC
                    ''', (user_id,))
                else:
                    cursor.execute('''
                        SELECT a.*, u.Nombres, u.Apellidos 
                        FROM alerta_sistema a
                        LEFT JOIN usuario u ON a.Solicitud_Permiso_Aprendiz_Usuario_Id_Usuario = u.Id_Usuario
                        ORDER BY a.fecha_generacion DESC
                    ''')
                alertas = cursor.fetchall()
                return jsonify(alertas)
        finally:
            conn.close()

class AlertaDetail(Resource):
    @role_required(['Administrador', 'Delegado'])
    def patch(self, alerta_id):
        data = request.get_json()
        nuevo_estado = data.get('estado')
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('''
                    UPDATE alerta_sistema 
                    SET estado_alerta = %s 
                    WHERE Id_Alerta_sistema = %s
                ''', (nuevo_estado, alerta_id))
                conn.commit()
                return {'message': 'Estado actualizado'}, 200
        except Exception as e:
            return {'message': str(e)}, 500
        finally:
            conn.close()

# Configuración de rutas
api.add_resource(Login, '/api/login')
api.add_resource(Usuario, '/api/usuario/<int:user_id>')
api.add_resource(PermisoList, '/api/permisos')
api.add_resource(PermisoDetail, '/api/permisos/<int:permiso_id>')
api.add_resource(TareaList, '/api/tareas')
api.add_resource(TareaDetail, '/api/tareas/<int:tarea_id>')
api.add_resource(AlertaList, '/api/alertas')
api.add_resource(AlertaDetail, '/api/alertas/<int:alerta_id>')

if __name__ == '__main__':
    app.run(debug=True)