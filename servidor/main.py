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

import socket
import threading
from auth import registrar_usuario, autenticar_usuario, derivar_clave
from crypto_servidor import guardar_cita_servidor, obtener_cita, borrar_cita_json, load_citas

def procesar_comando(comando):
    """Procesa comandos del cliente y devuelve respuesta"""
    partes = comando.split('|')
    cmd = partes[0]
    
    if cmd == "REGISTRO":
        usuario, password = partes[1], partes[2]
        exito = registrar_usuario(usuario, password)
        return "REGISTRO_EXITOSO" if exito else "REGISTRO_FALLIDO"
        
    elif cmd == "LOGIN":
        usuario, password = partes[1], partes[2]
        exito = autenticar_usuario(usuario, password)
        return "LOGIN_EXITOSO" if exito else "LOGIN_FALLIDO"
        
    elif cmd == "GUARDAR_CITA":
        usuario, fecha, motivo_cifrado = partes[1], partes[2], partes[3]
        fecha_dt = datetime.fromisoformat(fecha)
        exito = guardar_cita_servidor(usuario, fecha_dt, motivo_cifrado)
        return "CITA_GUARDADA" if exito else "ERROR_GUARDAR_CITA"
        
    elif cmd == "OBTENER_CITAS":
        usuario = partes[1]
        citas = load_citas()
        return str(citas.get(usuario, {}))
        
    else:
        return "COMANDO_DESCONOCIDO"

def manejar_cliente(client_socket):
    """Maneja la comunicación con un cliente"""
    try:
        while True:
            comando = client_socket.recv(1024).decode('utf-8')
            if not comando:
                break
                
            print(f"📨 Comando recibido: {comando}")
            respuesta = procesar_comando(comando)
            client_socket.send(respuesta.encode('utf-8'))
    except Exception as e:
        print(f"Error con cliente: {e}")
    finally:
        client_socket.close()

def iniciar_servidor():
    host = 'localhost'
    port = 5000
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"🖥️  Servidor escuchando en {host}:{port}")
        
        while True:
            client_socket, addr = server_socket.accept()
            print(f"🔗 Cliente conectado desde {addr}")
            # Manejar cliente en hilo separado
            threading.Thread(target=manejar_cliente, args=(client_socket,)).start()

if __name__ == '__main__':
    iniciar_servidor()