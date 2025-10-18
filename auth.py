import os
import json # Para leer/escribir users.json

# Para el hashing de la contraseña (Registro de usuario)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes

# Para derivar la clave de cifrado K (una vez autenticado)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Utilidades para conversión de bytes
import base64

def registrar_usuario(nombre_usuario, contrasena): 
    return True
def autenticar_usuario(nombre_usuario, contrasena):
    return True
def derivar_clave(contrasena_maestra, usuario_autenticado):
    return 1