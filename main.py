import sys
import getpass #para que no se lea la contraseña

# Importa las funciones que deben estar definidas en auth.py
from auth import registrar_usuario, autenticar_usuario, derivar_clave
# from crypto import logica_principal_aplicacion # Para el flujo posterior de Eval 2

def menu_principal():
    """
    Gestiona el bucle de la terminal para el inicio de sesión o registro.
    Retorna el nombre de usuario y la contraseña maestra si la autenticación es exitosa.
    """
    
    while True:
        # Petición inicial al usuario
        opcion = input("\nUsuario nuevo? (Si/No): ").strip().lower()

        if opcion in ['si', 's', 'sí']:
            # --- FLUJO DE REGISTRO ---
            print("\n--- REGISTRO DE NUEVO USUARIO ---")
            nombre_usuario = input("Introduce un nombre de usuario: ").strip()
            contrasena = getpass.getpass("Introduce una contraseña robusta: ").strip()
            
            if not nombre_usuario or not contrasena:
                print("El usuario y la contraseña no pueden estar vacíos. Inténtalo de nuevo.")
                continue

            if registrar_usuario(nombre_usuario, contrasena):
                print("\nRegistro exitoso.")
                print(f"Bienvenido al SecureCitas CLI, {nombre_usuario}!")
                # Si la autenticación es exitosa, se sale del bucle
                return nombre_usuario, contrasena 
            
        elif opcion in ['no', 'n']:
            # --- FLUJO DE INICIO DE SESIÓN ---
            print("\n--- INICIO DE SESIÓN ---")
            nombre_usuario = input("Usuario: ").strip()
            contrasena = getpass.getpass("Contraseña: ").strip()
            
            if not nombre_usuario or not contrasena:
                print("El usuario y la contraseña no pueden estar vacíos. Inténtalo de nuevo.")
                continue
            
            if autenticar_usuario(nombre_usuario, contrasena):
                print(f"Bienvenido al SecureCitas CLI, {nombre_usuario}!")
                # Si la autenticación es exitosa, se sale del bucle
                return nombre_usuario, contrasena 
            else:
                print("Error de autenticación: Usuario o contraseña incorrectos.")
                
        elif opcion in ['salir', 'exit', 'q']:
            print("Saliendo de la aplicación.")
            sys.exit(0)
            
        else:
            print("Opción no válida. Por favor, responde 'Si' o 'No'.")


def main():
    """
    Punto de entrada principal de la aplicación.
    Controla el flujo desde la autenticación hasta la lógica principal.
    """
    print("--- SecureCitas CLI - Gestor de Citas Cifradas ---")
    
    try:
        # 1. Gestionar la autenticación/registro
        usuario_autenticado, contrasena_maestra = menu_principal()
        
        # 2. Derivar la clave simétrica K usando la contraseña y el salt
        print("\n--- DERIVANDO CLAVE MAESTRA ---")
        clave_maestra_K = derivar_clave(contrasena_maestra, usuario_autenticado)
        
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