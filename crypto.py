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

def desencriptar_cita(usuario_autenticado:str ,clave_maestra_K:bytes, cita):