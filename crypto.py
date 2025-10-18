import os
import json # Para leer/escribir los datos de la cita cifrada

# Para el cifrado/descifrado AES-GCM (Requisitos 2 y 3)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Para manejo de errores de autenticación
from cryptography.exceptions import InvalidTag

# Utilidades para conversión
import base64