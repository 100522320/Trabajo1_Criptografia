# === Este es el main del cliente ===

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
LOG_FILENAME = os.path.join(os.path.dirname(__file__), 'seguridad.log')

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

# Importa las funciones de la aplicacion que deben estar definidas en funcionalidades.py
from funcionalidades_cliente import aplicacion, registrar_usuario, autenticar_usuario, derivar_clave
# from crypto import logica_principal_aplicacion # Para el flujo posterior de Eval 2

def contraseñas_iguales(contraseña1:str, contraseña2:str)->bool:
    """Comprueba que las 2 contraseñas sean iguales"""
    return (contraseña1 == contraseña2)

def contraseña_robusta(contraseña):
    """Comprueba que la contraseña sea robusta, cumpliendo los siguientes criterios:
    1. Mínimo 8 caracteres de longitud.
    2. Contiene al menos 1 dígito (número).
    3. Contiene al menos 1 letra mayúscula.
    """
    # 1. Verificar la longitud mínima (8 caracteres)
    if len(contraseña) < 8:
        return False
    
    # 2. Verificar al menos 1 número
    # Usa una expresión regular para buscar cualquier dígito [0-9]
    if not re.search(r"\d", contraseña):
        return False
        
    # 3. Verificar al menos 1 letra mayúscula
    # Usa una expresión regular para buscar cualquier letra mayúscula [A-Z]
    if not re.search(r"[A-Z]", contraseña):
        return False
        
    # Si pasa todas las comprobaciones, la contraseña es robusta
    return True

def menu_principal():
    """
    Gestiona el bucle de la terminal para el inicio de sesión o registro.
    Retorna el nombre de usuario y la contraseña maestra si la autenticación es exitosa.
    """
    # Limpiamos el buffer de entrada antes del primer input si estamos en un terminal interactivo real
    try:
        if sys.stdin.isatty():
            # Linux/Mac
            import termios
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except ImportError:
        try:
            # Windows
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getch()
        except ImportError:
            # Fallback genérico
            pass
    except Exception:
        pass
   
    while True:
        # Petición inicial al usuario
        opcion = input("\nUsuario nuevo? (Si/No): ").strip().lower()


        if opcion in {'si', 's', 'sí'}:
            # --- FLUJO DE REGISTRO ---
            print("\n--- REGISTRO DE NUEVO USUARIO ---")
            nombre_usuario = input("Introduce un nombre de usuario: ").strip()
            contraseña = getpass.getpass("Introduce una contraseña: ").strip()
            contraseña_repetir = getpass.getpass("Repite la contraseña: ").strip()
           
            if not nombre_usuario or not contraseña or not contraseña_repetir:
                logger.warning("Intento de registro con campos vacíos.")
                print("El usuario y las contraseñas no pueden estar vacíos. Inténtalo de nuevo.")
                continue

            if not contraseñas_iguales(contraseña,contraseña_repetir):
                logger.warning("Fallo de registro: Contraseñas no coinciden.")
                print("Las contraseñas deben ser iguales. Inténtalo de nuevo.")
                continue

            if not contraseña_robusta(contraseña):
                logger.warning("Fallo de registro: Contraseña no robusta.")
                print("La contraseña debe ser de minimo 8 caracteres, con 1 numero y 1 mayuscula. Inténtalo de nuevo.")
                continue

            if registrar_usuario(nombre_usuario, contraseña):
                print("\nRegistro exitoso.")
                print(f"Bienvenido a SecureCitas CLI, {nombre_usuario}!")
                # Si la autenticación es exitosa, se sale del bucle
                return nombre_usuario, contraseña
            print("Este usuario ya existe. Por favor inicie sesion.")
           
        elif opcion in {'no', 'n'}:
            # --- FLUJO DE INICIO DE SESIÓN ---
            print("\n--- INICIO DE SESIÓN ---")
            nombre_usuario = input("Usuario: ").strip()
            contraseña = getpass.getpass("Contraseña: ").strip()
           
            if not nombre_usuario or not contraseña:
                logger.warning("Intento de login con campos vacíos.")
                print("El usuario y la contraseña no pueden estar vacíos. Inténtalo de nuevo.")
                continue
           
            if autenticar_usuario(nombre_usuario, contraseña):
                print(f"Bienvenido a SecureCitas CLI, {nombre_usuario}!")
                # Si la autenticación es exitosa, se sale del bucle
                return nombre_usuario, contraseña
            
               
        elif opcion in ['salir', 'exit', 'q']:
            logger.info("El usuario ha salido de la aplicación.")
            print("Saliendo de la aplicación.")
            sys.exit(0)
           
        else:
            print("\nOpción no válida. Por favor, responde 'Si' o 'No'")

def main():
    """
    Punto de entrada principal de la aplicación.
    Controla el flujo desde la autenticación hasta la lógica principal.
    """
    print("--- SecureCitas CLI - Gestor de citas medicas cifradas ---")
   
    try:
        # 1. Gestionar la autenticación/registro
        usuario_autenticado, contraseña_maestra = menu_principal()

        # 2. Derivar la clave simétrica K usando la contraseña y el salt
        clave_maestra_K = derivar_clave(contraseña_maestra, usuario_autenticado)

        if not clave_maestra_K:
            logger.critical("No se pudo derivar la clave K. Saliendo.")
            print("Ha ocurrido un error en el sistema.")
            return

        # 3. Iniciar la lógica de la aplicación
        aplicacion(usuario_autenticado,clave_maestra_K)

        
       
        

    except SystemExit:
        # Captura la salida si el usuario usa 'q' o 'salir' en el menú.
        pass
    except Exception as e:
        logger.fatal(f"\nHa ocurrido un error fatal: {e}", exc_info=True)
        print(f"\nHa ocurrido un error fatal: {e}")




if __name__ == '__main__':
    main()