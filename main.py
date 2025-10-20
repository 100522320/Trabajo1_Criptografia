import sys
import re
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
                print("El usuario y las contraseñas no pueden estar vacíos. Inténtalo de nuevo.")
                continue

            if not contraseñas_iguales(contraseña,contraseña_repetir):
                print("Las contraseñas deben ser iguales. Inténtalo de nuevo.")
                continue

            if not contraseña_robusta(contraseña):
                print("La contraseña debe ser de minimo 8 caracteres, con 1 numero y 1 mayuscula. Inténtalo de nuevo.")
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




if __name__ == '__main__':
    main()