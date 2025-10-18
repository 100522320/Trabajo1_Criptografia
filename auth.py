import os
import json # Para leer/escribir users.json

# Para el hashing de la contraseña (Registro de usuario)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.primitives.kdf.argon2 import SaltAndIterations

# Para derivar la clave de cifrado K (una vez autenticado)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Utilidades para conversión de bytes
import base64