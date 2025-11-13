import os
import json # Para leer/escribir los datos de la cita cifrada
from datetime import datetime
import logging # Importamos el módulo de logging

# Para el cifrado/descifrado AES-GCM (Requisitos 2 y 3)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Para manejo de errores de autenticación
from cryptography.exceptions import InvalidTag

# Para el establecimineto de la clave simétrica de comunicación
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Utilidades para conversión
import base64

# Obtener el logger configurado en main.py
logger = logging.getLogger('SecureCitasCLI')

#-----------------------------
#        Configuracion 
#-----------------------------
# Obtenemos el directorio donde está este archivo
current_dir = os.path.dirname(os.path.abspath(__file__))
# Construimos la ruta al archivo de usuarios
CITAS_FILE = os.path.join(current_dir, 'jsons', 'citas.json')
LONGITUD_AES_NONCE = 12

def load_citas() -> dict:
    """
    Carga el diccionario de citas desde el archivo JSON.
    Devuelve un diccionario vacío si el archivo no existe o está corrupto.
    """
    try:
        with open(CITAS_FILE, 'r') as f:
            # Intenta cargar los datos del archivo
            citas = json.load(f)
            # Asegura que lo cargado sea un diccionario (manejo de archivos mal formados)
            if not isinstance(citas, dict):
                logger.warning(f"Archivo {CITAS_FILE} corrupto o no es un diccionario.")
                return {}
            return citas
    except (FileNotFoundError, json.JSONDecodeError):
        # Devuelve un diccionario vacío si el archivo no existe o no es JSON válido
        logger.warning(f"Archivo de citas no encontrado o JSON inválido: {CITAS_FILE}. Creando uno nuevo.")
        return {}

def guardar_cita(usuario: str, fecha: datetime, motivo_encriptado: str) -> bool:
    try:
        # Guardamos los datos de la cita
        citas = load_citas()
        if usuario not in citas:
            citas[usuario] = {}
        
        fecha_clave = fecha.isoformat()
        
        citas[usuario][fecha_clave] = motivo_encriptado
        
        with open(CITAS_FILE, 'w') as f:
            json.dump(citas, f, indent=4)
        logger.info(f"Cita guardada para {usuario} en {fecha_clave}. Datos cifrados en JSON.")
        return True
    except Exception as e:
        logger.error(f"Error al guardar la cita: {e}")
        return False

def obtener_cita(usuario: str, fecha: datetime) -> str:
    # Busca en el JSON una cita para un usuario y fecha específicos y devuelve el motivo cifrado (string en Base64) si lo encuentra
    citas = load_citas()
    
    # Comprobamos que el usuario exista en el diccionario de citas
    if usuario in citas:
        # Convertimos la fecha a formato ISO para buscar la clave en el JSON
        fecha_clave = fecha.isoformat()
        
        # Usamos .get() para buscar la clave; devuelve None si no la encuentra
        return citas[usuario].get(fecha_clave)
        
    # Si el usuario no tiene ninguna cita, devolvemos None
    return None

def borrar_cita_json(usuario: str, fecha: datetime) -> bool:
    # Elimina una cita del archivo JSON
    try:
        citas = load_citas()
        if usuario in citas:
            fecha_clave = fecha.isoformat()
            if fecha_clave in citas[usuario]:
                del citas[usuario][fecha_clave]
                with open(CITAS_FILE, 'w') as f:
                    json.dump(citas, f, indent=4)
                logger.info(f"Cita de {usuario} en {fecha_clave} eliminada del JSON.")
                return True
        logger.warning(f"Intento de eliminar cita de {usuario} en {fecha.isoformat()} fallido (no encontrada).")
        return False
    except Exception as e:
        logger.error(f"Error al eliminar la cita de la base de datos: {e}")
        return False

# Variables globales para las claves del servidor
clave_privada_servidor = None
clave_publica_servidor = None

def generar_par_claves():
    """Genera par de claves RSA para el servidor"""
    global clave_privada_servidor, clave_publica_servidor
    clave_privada_servidor = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    clave_publica_servidor = clave_privada_servidor.public_key()

def serializar_clave_publica():
    """Serializa la clave pública del servidor"""
    return clave_publica_servidor.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserializar_clave_publica(clave_publica_bytes):
    """Deserializa una clave pública del cliente"""
    return serialization.load_pem_public_key(clave_publica_bytes)

def desencriptar_asimetrico(mensaje_cifrado: str) -> str:
    """Descifra un mensaje con la clave privada del servidor"""
    try:
        mensaje_bytes = base64.b64decode(mensaje_cifrado.encode('utf-8'))
        mensaje_descifrado = clave_privada_servidor.decrypt(
            mensaje_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return mensaje_descifrado.decode('utf-8')
    except Exception as e:
        logger.error(f"Error durante el descifrado asimétrico: {e}")
        return None

def encriptar_mensaje(clave: bytes, mensaje: str) -> str:
    """Cifra un mensaje para comunicación segura con el cliente"""
    try:
        nonce = os.urandom(LONGITUD_AES_NONCE)
        cifrador = Cipher(algorithms.AES(clave), modes.GCM(nonce), backend=default_backend())
        encriptador = cifrador.encryptor()
        texto_cifrado = encriptador.update(mensaje.encode('utf-8')) + encriptador.finalize()
        tag = encriptador.tag
        
        resultado = base64.b64encode(nonce + tag + texto_cifrado).decode('utf-8')
        logger.debug(f"Mensaje cifrado. Longitud original: {len(mensaje)}, longitud cifrada: {len(resultado)}")
        return resultado
        
    except Exception as e:
        logger.error(f"Error durante el cifrado del mensaje: {e}")
        return None

def desencriptar_mensaje(clave: bytes, mensaje_cifrado: str) -> str:
    """Descifra un mensaje recibido del cliente"""
    try:
        datos = base64.b64decode(mensaje_cifrado.encode('utf-8'))
        nonce = datos[:LONGITUD_AES_NONCE]
        tag = datos[LONGITUD_AES_NONCE:LONGITUD_AES_NONCE + 16]
        texto_cifrado = datos[LONGITUD_AES_NONCE + 16:]
        
        cifrador = Cipher(algorithms.AES(clave), modes.GCM(nonce, tag), backend=default_backend())
        desencriptador = cifrador.decryptor()
        texto_plano = desencriptador.update(texto_cifrado) + desencriptador.finalize()
        return texto_plano.decode('utf-8')
    except Exception as e:
        logger.error(f"Error durante el descifrado del mensaje: {e}")
        return None
