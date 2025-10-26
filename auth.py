import os
import json # Para leer/escribir users.json
import logging #Importamos el módulo de logging

# Para el hashing de la contraseña (Registro de usuario)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes

# Para derivar la clave de cifrado K (una vez autenticado)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Utilidades para conversión de bytes
import base64

#Obtener el logger configurado en main.py
logger = logging.getLogger('SecureCitasCLI')

#-----------------------------
#        Configuracion 
#-----------------------------
USERS_FILE = './jsons/usuarios.json'
SALT_LENGTH = 16 # 16 bytes para el salt
# Parametros para Argon2id
M_COST = 524288  # Coste de memoria (512 MB ya que la unidad es KB)
T_COST = 3      # Coste de tiempo (numero de iteraciones)
P_COST = 4      # Paralelismo (numero de threads)
HASH_LENGTH = 32 # Longitud de la clave derivada
# Parametros para PBKDF2
KEY_K_LENGTH = 32 # Longitud deseada para la clave simétrica (32 bytes = 256 bits para AES-256)
PBKDF2_ITERATIONS = 600000 # Número de iteraciones para PBKDF2.


def load_users() -> dict:
    """
    Carga el diccionario de usuarios desde el archivo JSON.
    Devuelve un diccionario vacío si el archivo no existe o está corrupto.
    """
    try:
        with open(USERS_FILE, 'r') as f:
            # Intenta cargar los datos del archivo
            users = json.load(f)
            # Asegura que lo cargado sea un diccionario
            if not isinstance(users, dict):
                logger.warning(f"Archivo {USERS_FILE} corrupto o no es un diccionario.")
                return {}
            return users
    except (FileNotFoundError, json.JSONDecodeError):
        # Devuelve un diccionario vacío si el archivo no existe o no es JSON válido
        logger.warning(f"Archivo de usuarios no encontrado o JSON inválido: {USERS_FILE}. Creando uno nuevo.")
        return {}

def hashear_contraseña(salt: bytes,contraseña: str) -> bytes | None:
    """
    Recibe un salt (bytes) y una contraseña (str) y devuelve su hash
    """
    # 1.Mensaje de depuración con el algoritmo y parámetros (Requisito 2)
    logger.debug(
        f"OPERACIÓN: Hashing de Contraseña | ALGORITMO: Argon2id "
        f"| PARÁMETROS: Memoria={M_COST/1024/1024}MB, Tiempo={T_COST}, Paralelismo={P_COST}."
    )
    
    #Instanciar la Función de Derivación de Clave (KDF) Argon2id
    kdf = Argon2id(
        salt=salt,
        memory_cost=M_COST,
        iterations=T_COST,
        lanes=P_COST,
        length=HASH_LENGTH
    )

    #Hashear la contraseña
    #Argon2id.derive espera bytes, por lo que se codifica la cadena de la contraseña.
    try:
        contraseña_bytes = contraseña.encode('utf-8')
        contraseña_hash = kdf.derive(contraseña_bytes)
        
        # Mensaje de depuración con el resultado (el hash, truncado)
        logger.debug(f"RESULTADO DEL HASH: {base64.b64encode(contraseña_hash).decode('utf-8')} Bytes: {len(contraseña_hash)}.")
        
    except Exception as e:
        logger.error(f"Error durante el hasheo de la contraseña: {e}")
        return None
    
    return contraseña_hash

def registrar_usuario(nombre_usuario: str, contraseña: str) -> bool:
    """
    Genera un salt seguro, hashea la contraseña usando Argon2id y
    almacena el nombre de usuario, el salt y el hash en un archivo JSON.
    """
    # 1.Generamos el salt
    salt = os.urandom(SALT_LENGTH)
    logger.debug(f"Salt aleatorio generado para '{nombre_usuario}': {base64.b64encode(salt).decode('utf-8')} ({SALT_LENGTH} bytes).")
    
    # 2. Hashear la contraseña
    contraseña_hash = hashear_contraseña(salt,contraseña)
    if not contraseña_hash:
        return False

    # 3. Preparar los datos para el almacenamiento
    # La codificación Base64 convierte bytes (salt, hash) en cadenas seguras.
    datos_usuario = {
        'nombre_usuario': nombre_usuario,
        # Almacenar como cadena base64
        'salt': base64.b64encode(salt).decode('utf-8'),
        # Almacenar como cadena base64
        'hash': base64.b64encode(contraseña_hash).decode('utf-8')
    }
   
    # 4. Cargar usuarios existentes o crear un diccionario vacío
    users = load_users()

    # Verificar si el usuario ya existe
    if nombre_usuario in users:
        logger.warning(f"Error de registro: El usuario '{nombre_usuario}' ya existe.")
        print("Este usuario ya existe. Por favor inicie sesion.")
        return False
       
    # 5. Almacenar el nombre de usuario y los datos en el diccionario de usuarios
    users[nombre_usuario] = datos_usuario
   
    # 6. Escribir el diccionario actualizado de nuevo en el archivo JSON
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)
        logger.info(f"Éxito: Usuario '{nombre_usuario}' registrado y almacenado.")
        return True
    except Exception as e:
        logger.error(f"Error al escribir en el archivo {USERS_FILE}: {e}")
        return False
   
def autenticar_usuario(nombre_usuario: str, contraseña: str) -> bool:
    """
    Autentica un usuario buscando su hash y salt, y usando Argon2id.verify() 
    para una comparación segura de contraseñas.
    """
    # 1. Buscamos al usuario en el json de usuarios
    users = load_users()
    if nombre_usuario not in users:
        logger.warning(f"Fallo de autenticación: Usuario '{nombre_usuario}' no existe.")
        return False
    
    # 2. Tomamos sus datos (salt y hash como cadenas Base64)
    try:
        salt_bytes = base64.b64decode(users[nombre_usuario]["salt"])
        hash_almacenado = base64.b64decode(users[nombre_usuario]["hash"])
    except Exception as e:
        logger.error(f"Error al decodificar Base64 de credenciales: {e}")
        return False

    # 3. Instanciar el KDF con el salt recuperado y los parámetros originales
    # Necesitamos el KDF para acceder al método verify().
    kdf = Argon2id(
        salt=salt_bytes,
        memory_cost=M_COST,
        iterations=T_COST,
        lanes=P_COST,
        length=HASH_LENGTH
    )
    
    # 4. Usar el método verify() para hashear la contraseña introducida 
    # y compararla de forma segura con el hash almacenado.
    logger.debug(f"OPERACIÓN: Verificación de Contraseña | ALGORITMO: Argon2id."
                f"| PARÁMETROS: Memoria={M_COST/1024/1024}MB, Tiempo={T_COST}, Paralelismo={P_COST}.")
    
    try:
        contraseña_bytes = contraseña.encode('utf-8')
        kdf.verify(contraseña_bytes, hash_almacenado)
        # Si verify() no lanza una excepción, la autenticación es exitosa.
        
        logger.info(f"Éxito de autenticación para '{nombre_usuario}'.")
        return True 
        
    except InvalidKey:
        # Esto ocurre cuando la contraseña introducida es incorrecta.
        logger.warning(f"Fallo de autenticación: Contraseña incorrecta para '{nombre_usuario}'.")
        return False
        
    except Exception as e:
        # Otros errores durante el proceso de verificación.
        logger.error(f"Error inesperado durante la verificación: {e}")
        return False


def derivar_clave(contraseña_maestra: str, usuario_autenticado: str)-> bytes | None:
    """
    Deriva la Clave Maestra de Cifrado (K) para el usuario autenticado
    a partir de su contraseña y el salt almacenado, usando PBKDF2HMAC.
    """

    #1.Obtenemos los datos del json de usuarios
    users = load_users()
    #No hace falta comprobar si el usuario existe porque esta funcion solo se llama cuando ya hemos autenticado esto
    try:    
        salt_bytes = base64.b64decode(users[usuario_autenticado]["salt"])
    except Exception as e:
        logger.error(f"Error al decodificar Base64 del salt para la derivación: {e}")
        return None
    
    # 2. Instanciar el KDF (Key Derivation Function) PBKDF2HMAC
    # Utilizamos el mismo salt que para el hashing, pero con PBKDF2.
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=KEY_K_LENGTH,
        salt=salt_bytes,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    
    # AÑADIDO: Mensaje de depuración con el algoritmo y la longitud de clave (Requisito 2)
    logger.debug(
        f"OPERACIÓN: Derivación de Clave Simétrica K | ALGORITMO: PBKDF2HMAC(SHA256) "
        f"| LONGITUD DE CLAVE FINAL: {KEY_K_LENGTH * 8} bits | ITERACIONES: {PBKDF2_ITERATIONS}."
    )
    
    # 3. Derivar la clave K
    try:
        contraseña_bytes = contraseña_maestra.encode('utf-8')
        clave_K = kdf.derive(contraseña_bytes)
        
        logger.info(f"Éxito: Clave Maestra K derivada, {base64.b64encode(clave_K).decode('utf-8')} ({KEY_K_LENGTH*8} bits).")
        
        return clave_K
        
    except Exception as e:
        logger.error(f"Error durante la derivación de clave con PBKDF2HMAC: {e}")
        return None
