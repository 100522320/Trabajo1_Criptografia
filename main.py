import sys
import os
import getpass #para que no se lea la contraseña

# =============================================================================
# ACTIVACIÓN AUTOMÁTICA DEL VENV - COMPATIBLE CON TODOS LOS SISTEMAS
# =============================================================================

def setup_venv():
    """Configura el venv de forma compatible con cualquier SO"""
    venv_base = os.path.join(os.path.dirname(__file__), '.venv')
   
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

# Importa las funciones que deben estar definidas en auth.py
from auth import registrar_usuario, autenticar_usuario, derivar_clave
# from crypto import logica_principal_aplicacion # Para el flujo posterior de Eval 2

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
            contraseña = getpass.getpass("Introduce una contraseña robusta: ").strip()
           
            if not nombre_usuario or not contraseña:
                print("El usuario y la contraseña no pueden estar vacíos. Inténtalo de nuevo.")
                continue


            if registrar_usuario(nombre_usuario, contraseña):
                print("\nRegistro exitoso.")
                print(f"Bienvenido al SecureCitas CLI, {nombre_usuario}!")
                # Si la autenticación es exitosa, se sale del bucle
                return nombre_usuario, contraseña
           
        elif opcion in {'no', 'n'}:
            # --- FLUJO DE INICIO DE SESIÓN ---
            print("\n--- INICIO DE SESIÓN ---")
            nombre_usuario = input("Usuario: ").strip()
            contraseña = getpass.getpass("Contraseña: ").strip()
           
            if not nombre_usuario or not contraseña:
                print("El usuario y la contraseña no pueden estar vacíos. Inténtalo de nuevo.")
                continue
           
            if autenticar_usuario(nombre_usuario, contraseña):
                print(f"Bienvenido al SecureCitas CLI, {nombre_usuario}!")
                # Si la autenticación es exitosa, se sale del bucle
                return nombre_usuario, contraseña
            
               
        elif opcion in ['salir', 'exit', 'q']:
            print("Saliendo de la aplicación.")
            sys.exit(0)
           
        else:
            print("\nOpción no válida. Por favor, responde 'Si' o 'No'")

def main():
    """
    Punto de entrada principal de la aplicación.
    Controla el flujo desde la autenticación hasta la lógica principal.
    """
    print("--- SecureCitas CLI - Gestor de Citas Cifradas ---")
   
    try:
        # 1. Gestionar la autenticación/registro
        usuario_autenticado, contraseña_maestra = menu_principal()

        #-------------------------------------------
        #     A PARTIR DE AQUI NO ESTA BIEN
        #-------------------------------------------

        # 2. Derivar la clave simétrica K usando la contraseña y el salt
        print("\n--- DERIVANDO CLAVE MAESTRA ---")
        clave_maestra_K = derivar_clave(contraseña_maestra, usuario_autenticado)
       
        # 3. Iniciar la lógica de la aplicación (consulta/edición de citas)
        # Aquí iría el código de la segunda fase (Eval 2)
        # logica_principal_aplicacion(usuario_autenticado, clave_maestra_K)
       
        print(f"\nUsuario '{usuario_autenticado}' listo para operar con la clave K.")


    except SystemExit:
        # Captura la salida si el usuario usa 'q' o 'salir' en el menú.
        pass
    except Exception as e:
        print(f"\nHa ocurrido un error fatal: {e}")




# Este es el estándar de Python para ejecutar la función principal
if __name__ == '__main__':
    main()