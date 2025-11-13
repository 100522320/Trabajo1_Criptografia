# === Este es el main del servidor ===

import datetime
import socket
import threading
import sys
import re
import os
import getpass #para que no se lea la contraseña
import logging # AÑADIDO: Importamos el módulo de logging

# =============================================================================
# ACTIVACIÓN AUTOMÁTICA DEL VENV - COMPATIBLE CON TODOS LOS SISTEMAS
# =============================================================================

def setup_venv():
    """Configura el venv de forma compatible con cualquier SO"""
    # Buscar el .venv en el directorio actual o padres
    current_dir = os.getcwd()
    venv_base = None
    
    # Buscar en directorio actual y padres
    for dir_path in [current_dir] + [os.path.dirname(current_dir)]:
        possible_venv = os.path.join(dir_path, '.venv')
        if os.path.exists(possible_venv):
            venv_base = possible_venv
            break
    
    if not venv_base:
        return False
   
    # Posibles rutas de site-packages según el SO
    possible_paths = []
   
    # Linux/Mac paths
    python_versions = [
        f"python{sys.version_info.major}.{sys.version_info.minor}",
        f"python{sys.version_info.major}",
        "python3"
    ]
   
    for py_version in python_versions:
        possible_paths.append(os.path.join(venv_base, 'lib', py_version, 'site-packages'))
   
    # Windows paths
    possible_paths.append(os.path.join(venv_base, 'Lib', 'site-packages'))
   
    # Buscar la primera ruta que exista
    for path in possible_paths:
        if os.path.exists(path):
            sys.path.insert(0, path)
            return True
   
    return False

# Intentar configurar el venv
if not setup_venv():
    print("AVISO: No se encontró el venv, usando Python del sistema")

# =============================================================================
# CONFIGURACIÓN DEL SISTEMA DE LOGGING
# La práctica pide mostrar el resultado en un log o mensaje de depuración junto
# con el algoritmo y la longitud de clave.
# =============================================================================
LOG_FILENAME = 'seguridad.log'

# Crear el logger principal y configurar el nivel más bajo (DEBUG)
logger = logging.getLogger('SecureCitasCLI')
logger.setLevel(logging.DEBUG)

# Handler para Archivo (DEBUG: guarda toda la información)
file_handler = logging.FileHandler(LOG_FILENAME, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)

# Formato del log (hora, nivel, nombre del módulo, mensaje)
formatter = logging.Formatter(
    '[%(asctime)s] - %(levelname)s - %(name)s - %(message)s'
)
file_handler.setFormatter(formatter)

# Evitar añadir handlers múltiples veces
if not logger.handlers:
    logger.addHandler(file_handler)

logger.debug("Sistema de logging 'SecureCitasCLI' inicializado.")
# =============================================================================

import logging
from funcionalidades_servidor import Servidor

if __name__ == '__main__':
    servidor = Servidor()
    servidor.iniciar()