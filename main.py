import sys # Para salir de la aplicación
import json # Para manejo general de datos (p. ej. archivos de citas)

# Importar las funciones que se van a usar
from auth import (
    register_user, 
    authenticate_user, 
    derive_key
)
from crypto import (
    encrypt_appointment, 
    decrypt_appointment
)

# Puedes añadir más imports si manejas la salida con colores, etc.