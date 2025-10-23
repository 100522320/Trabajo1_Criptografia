import os
import json # Para leer/escribir los datos de la cita cifrada
from datetime import datetime

# Para el cifrado/descifrado AES-GCM (Requisitos 2 y 3)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Para manejo de errores de autenticación
from cryptography.exceptions import InvalidTag

# Utilidades para conversión
import base64

#-----------------------------
#        Configuracion 
#-----------------------------
CITAS_FILE = './jsons/citas.json'

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
                return {}
            return citas
    except (FileNotFoundError, json.JSONDecodeError):
        # Devuelve un diccionario vacío si el archivo no existe o no es JSON válido
        return {}

def encriptar_cita(usuario_autenticado:str ,clave_maestra_K:bytes, fecha:datetime):
    try:
        # Convertimos la fecha a un string estándar y luego a bytes para poder cifrarlo
        plaintext = fecha.isoformat().encode('utf-8')

        # Generamos un 'nonce' aleatorio
        nonce = os.urandom(12)
        # Configuramos el cifrador AES-GCM para que use la librería AES con nuestra clave maestra (clave_maestra_K),
        # con el modo de operación GCM, pasándole el nonce que acabamos de generar
        cipher = Cipher(algorithms.AES(clave_maestra_K), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        # Ciframos el texto plano
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Obtenemos el 'tag' de autenticación
        tag = encryptor.tag
        # Concatenamos nonce, tag y el texto cifrado en un único bloque de bytes para almacenarlos juntos y lo codificamos todo en Base64 
        # para convertir esos bytes en un string seguro que podemos guardar sin problemas en un archivo JSON
        encrypted_data = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        
        print("¡Cita cifrada con éxito!")
        return encrypted_data

    except Exception as e:
        print(f"Error durante el cifrado de la cita: {e}")
        return None

def desencriptar_cita(usuario_autenticado:str ,clave_maestra_K:bytes, cita):
    return