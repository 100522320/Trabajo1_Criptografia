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
from funcionalidades_cliente import aplicacion, registrar_usuario, autenticar_usuario, derivar_clave, cerrar_cliente

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
    try:
        if sys.stdin.isatty():
            import termios
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except ImportError:
        try:
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getch()
        except ImportError:
            pass
    except Exception:
        pass
   
    while True:
        try:
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

                print("\n🔄 Conectando con el servidor...")
                if registrar_usuario(nombre_usuario, contraseña):
                    print("✅ Registro exitoso.")
                    print(f"🎉 Bienvenido a SecureCitas CLI, {nombre_usuario}!")
                    return nombre_usuario, contraseña
                
                print("❌ Este usuario ya existe. Por favor inicie sesion.")
                cerrar_cliente()
               
            elif opcion in {'no', 'n'}:
                # --- FLUJO DE INICIO DE SESIÓN ---
                print("\n--- INICIO DE SESIÓN ---")
                nombre_usuario = input("Usuario: ").strip()
                contraseña = getpass.getpass("Contraseña: ").strip()
               
                if not nombre_usuario or not contraseña:
                    logger.warning("Intento de login con campos vacíos.")
                    print("El usuario y la contraseña no pueden estar vacíos. Inténtalo de nuevo.")
                    continue
               
                print("\n🔄 Conectando con el servidor...")
                if autenticar_usuario(nombre_usuario, contraseña):
                    print(f"✅ Autenticación exitosa.")
                    print(f"🎉 Bienvenido a SecureCitas CLI, {nombre_usuario}!")
                    return nombre_usuario, contraseña
                
                print("❌ Usuario o contraseña incorrectos.")
                cerrar_cliente()
                   
            elif opcion in ['salir', 'exit', 'q']:
                logger.info("El usuario ha salido de la aplicación.")
                print("Saliendo de la aplicación.")
                cerrar_cliente()
                sys.exit(0)
               
            else:
                print("\n⚠️  Opción no válida. Por favor, responde 'Si' o 'No'")
        
        except ConnectionError as e:
            logger.error(f"Error de conexión durante autenticación: {e}")
            print(f"\n❌ ERROR DE CONEXIÓN")
            print(f"No se pudo conectar con el servidor.")
            print(f"Detalles: {e}")
            print(f"\nPor favor, verifique que el servidor esté en ejecución e intente de nuevo.")
            cerrar_cliente()
            # Permitir intentar de nuevo en lugar de salir
        except Exception as e:
            logger.error(f"Error inesperado en menu_principal: {e}", exc_info=True)
            print(f"\n❌ Error inesperado: {e}")
            print("Por favor, inténtelo de nuevo.")

def main():
    """
    Punto de entrada principal de la aplicación.
    Controla el flujo desde la autenticación hasta la lógica principal.
    """
    print("╔════════════════════════════════════════════════════════════╗")
    print("║     SecureCitas CLI - Gestor de citas médicas cifradas     ║")
    print("╚════════════════════════════════════════════════════════════╝")
   
    try:
        # 1. Gestionar la autenticación/registro
        usuario_autenticado, contraseña_maestra = menu_principal()

        # 2. Derivar la clave simétrica K usando la contraseña y el salt
        print("\n🔐 Derivando clave de cifrado...")
        clave_maestra_K = derivar_clave(contraseña_maestra, usuario_autenticado)

        if not clave_maestra_K:
            logger.critical("No se pudo derivar la clave K. Saliendo.")
            print("❌ Ha ocurrido un error en el sistema de cifrado.")
            cerrar_cliente()
            return

        print("✅ Sistema de cifrado inicializado correctamente.")
        print("🔒 Conexión segura establecida con el servidor.\n")

        # 3. Iniciar la lógica de la aplicación
        aplicacion(usuario_autenticado, clave_maestra_K)

    except ConnectionError as e:
        # Error de conexión durante el uso de la aplicación
        logger.error(f"Desconexión inesperada: {e}")
        print("\n" + "="*60)
        
        # Verificar si fue cierre intencional del servidor
        if "se está cerrando" in str(e).lower():
            print("🛑 EL SERVIDOR SE HA CERRADO")
            print("="*60)
            print("El servidor ha sido detenido por el administrador.")
        else:
            print("⚠️  DESCONEXIÓN INESPERADA DEL SERVIDOR")
            print("="*60)
            print("La conexión con el servidor se ha perdido.")
            print("Posibles causas:")
            print("  • El servidor se cerró inesperadamente")
            print("  • Problemas de red")
            print("  • Timeout de conexión")
        
        print("\nLa aplicación se cerrará por seguridad.")
        print("="*60)
        cerrar_cliente()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupción del usuario detectada (Ctrl+C)")
        logger.info("Aplicación interrumpida por el usuario (Ctrl+C)")
        print("🔒 Cerrando conexión segura...")
        cerrar_cliente()
        print("👋 Hasta pronto!")
        
    except SystemExit:
        pass
        
    except Exception as e:
        logger.fatal(f"Error fatal inesperado: {e}", exc_info=True)
        print("\n" + "="*60)
        print("❌ ERROR FATAL")
        print("="*60)
        print(f"Ha ocurrido un error inesperado: {e}")
        print("Por favor, consulte el archivo de log 'seguridad.log'")
        print("para más detalles.")
        print("="*60)
        cerrar_cliente()

if __name__ == '__main__':
    main()