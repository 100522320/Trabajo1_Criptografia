import os
import json # Para leer/escribir users.json

# Para el hashing de la contraseña (Registro de usuario)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
#sfrom cryptography.hazmat.primitives.kdf.argon2 import InvalidKeyError
from cryptography.hazmat.primitives import hashes

# Para derivar la clave de cifrado K (una vez autenticado)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Utilidades para conversión de bytes
import base64

# --- Configuracion ---
USERS_FILE = './jsons/usuarios.json'
SALT_LENGTH = 16 # 16 bytes para el salt
# Parametros para Argon2id
M_COST = 524288  # Coste de memoria (512 MB ya que la unidad es KB)
T_COST = 3      # Coste de tiempo (numero de iteraciones)
P_COST = 4      # Paralelismo (numero de threads)
HASH_LENGTH = 32 # Longitud de la clave derivada

def registrar_usuario(nombre_usuario, contraseña):
    """
    Genera un salt seguro, hashea la contraseña usando Argon2id y
    almacena el nombre de usuario, el salt y el hash en un archivo JSON.
    """
    # 1.Generamos el salt
    salt = os.urandom(SALT_LENGTH)


    # 2. Instanciar la Función de Derivación de Clave (KDF) Argon2id
    kdf = Argon2id(
        salt=salt,
        memory_cost=M_COST,
        iterations=T_COST,
        lanes=P_COST,
        length=HASH_LENGTH
    )


    # 3. Hashear la contraseña
    #Argon2id.derive espera bytes, por lo que se codifica la cadena de la contraseña.
    try:
        contraseña_bytes = contraseña.encode('utf-8')
        contraseña_hash = kdf.derive(contraseña_bytes)
    except Exception as e:
        print(f"Error durante el hasheo de la contraseña: {e}")
        return False


    # 4. Preparar los datos para el almacenamiento
    # La codificación Base64 convierte bytes (salt, hash) en cadenas seguras.
    datos_usuario = {
        'nombre_usuario': nombre_usuario,
        # Almacenar como cadena base64
        'salt': base64.b64encode(salt).decode('utf-8'),
        # Almacenar como cadena base64
        'hash': base64.b64encode(contraseña_hash).decode('utf-8')
    }
   
    # 5. Cargar usuarios existentes o crear un diccionario vacío
    try:
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        users = {}


    # Verificar si el usuario ya existe
    if nombre_usuario in users:
        print(f"Error: El usuario '{nombre_usuario}' ya existe.")
        return False
       
    # 6. Almacenar el nombre de usuario y los datos en el diccionario de usuarios
    users[nombre_usuario] = datos_usuario
   
    # 7. Escribir el diccionario actualizado de nuevo en el archivo JSON
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)
        print(f"Éxito: Usuario '{nombre_usuario}' registrado.")
        return True
    except Exception as e:
        print(f"Error al escribir en el archivo {USERS_FILE}: {e}")
        return False
   
def autenticar_usuario(nombre_usuario, contraseña):
    return True
def derivar_clave(contraseña_maestra, usuario_autenticado):
    return 1

