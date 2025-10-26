from datetime import datetime
import json # Para leer/escribir los datos de la cita cifrada
# Utilidades para conversión
import base64
#importamos de crypto.py algunas funciones para encriptar y desencriptar las citas
from crypto import encriptar_cita,desencriptar_cita,load_citas,guardar_cita, obtener_cita, borrar_cita_json


def aplicacion(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    """
    Se encarga de dar funcionalidades a la aplicacion:
    Ver citas, editarlas, crearlas y borrarlas.
    """

    while True:
        print("Cosas que puede hacer:")
        print("1.Ver mis citas pendientes")
        print("2.Crear cita")
        print("3.Editar cita")
        print("4.Eliminar cita")
        print("5.Salir de la aplicacion")
        eleccion = input("¿Que desea hacer?:").strip()

        match eleccion:
            case '1':
                ver_citas_pendientes(usuario_autenticado,clave_maestra_K)
            case '2':
                crear_cita(usuario_autenticado,clave_maestra_K)
            case '3':
                editar_cita(usuario_autenticado,clave_maestra_K)
            case '4':
                eliminar_cita(usuario_autenticado)
            case '5':
                #solo salimos del bucle cuando el usuario lo indique
                print("Que tenga un buen dia.")
                return
            case _:
                print("Porfavor introduzca un numero del 1 al 5.\n")


def ver_citas_pendientes(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    '''
    Mostramos todas las citas que el usuario tenga pendientes
    (si se le ha pasado la fecha no se muestran)
    '''
    citas = load_citas()
    if usuario_autenticado not in citas or not citas[usuario_autenticado]:
        print("\nNo tiene ninguna cita guardada.")
        return

    citas_pendientes = []
    print("\n--- TUS CITAS PENDIENTES ---")

    # Iteramos sobre la fecha (clave) y el motivo cifrado (valor)
    for fecha_str, motivo_cifrado in citas[usuario_autenticado].items():
        fecha_cita = datetime.fromisoformat(fecha_str)
        if fecha_cita >= datetime.now():
            # Desciframos el motivo
            motivo_descifrado = desencriptar_cita(clave_maestra_K, motivo_cifrado)
            if motivo_descifrado:
                citas_pendientes.append((fecha_cita, motivo_descifrado))
            else:
                # Si falla el descifrado, lo indicamos
                citas_pendientes.append((fecha_cita, "[ERROR AL LEER MOTIVO]"))

    if not citas_pendientes:
        print("No tiene citas pendientes.")
        return

    # Ordenamos por fecha para mostrarlas cronológicamente
    citas_pendientes.sort(key=lambda item: item[0])

    for i, (fecha, motivo) in enumerate(citas_pendientes):
        print(f"{i+1}. {fecha.strftime('%d/%m/%Y a las %H:%M')} -> {motivo}")

    print(f"\nTotal: {len(citas_pendientes)} cita(s) pendiente(s).")

    return

def crear_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    # Fecha de la cita
    fecha_str = input("¿En que fecha y hora quiere la cita?(DD/MM/YYYY hh:mm):")
    
    try:
        fecha = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
    except ValueError:
        print("\nError: El formato de la fecha no es correcto. Use DD/MM/YYYY hh:mm.")
        return

    #La unica fecha imposible será anterior o igual a ahora, las demas las damos como buenas
    if fecha <= datetime.now():
        print("La fecha introducida no es valida (ya ha pasado). Porfavor intentelo de nuevo.")
        return
    
    # Motivo de la cita (lo que se va a cifrar)
    motivo = input("Introduzca el motivo de la cita: ").strip()
    if not motivo:
        print("El motivo no puede estar vacío.")
        return
    
    # Añadimos la cita encriptada a citas.json
    motivo_cifrado = encriptar_cita(clave_maestra_K, motivo)
    if motivo_cifrado:
        guardar_cita(usuario_autenticado, fecha, motivo_cifrado)
        print("\n¡Cita guardada con éxito!")
    else:
        print("\nError: No se pudo cifrar la cita.")

    return
    
def editar_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    # Pedimos la fecha de la cita a editar
    fecha_str = input("¿Qué fecha y hora tiene la cita que desea editar? (DD/MM/YYYY hh:mm): ")
    try:
        fecha_antigua = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
    except ValueError:
        print("Formato de fecha incorrecto.")
        return
        
    # Pedimos los nuevos datos
    print("--- Introduzca los nuevos datos de la cita ---")
    nueva_fecha_str = input("Nueva fecha y hora (dejar en blanco para no cambiar): ").strip()
    nuevo_motivo = input("Nuevo motivo (dejar en blanco para no cambiar): ").strip()

    # Si no se introduce nada, salimos
    if not nueva_fecha_str and not nuevo_motivo:
        print("No se ha realizado ningún cambio.")
        return
        
    # Preparamos los nuevos datos y guardarlos
    fecha_final = fecha_antigua
    if nueva_fecha_str:
        try:
            fecha_final = datetime.strptime(nueva_fecha_str, "%d/%m/%Y %H:%M")
        except ValueError:
            print("Formato de nueva fecha incorrecto. Se cancela la edición.")
            return
    
    # Comprobamos si la cita existe y obtenemos el motivo cifrado antiguo antes de borrar nada
    motivo_cifrado_antiguo = obtener_cita(usuario_autenticado, fecha_antigua)
    if motivo_cifrado_antiguo is None:
        print("No se ha encontrado ninguna cita en esa fecha.")
        return
    
    # Eliminamos la cita antigua
    if not borrar_cita_json(usuario_autenticado, fecha_antigua):
        print("Error: No se pudo eliminar la cita antigua para actualizarla.")
        return

    # Si no hay motivo nuevo, hay que descifrar el antiguo para volverlo a cifrar con la nueva fecha
    motivo_final = nuevo_motivo
    if not nuevo_motivo:
        motivo_final = desencriptar_cita(clave_maestra_K, motivo_cifrado_antiguo)
        if motivo_final is None:
            print("\nError: No se pudo leer el motivo original de la cita. Edición cancelada.")
            return
    
    # Ciframos y guardamos la "nueva" cita
    nuevo_motivo_cifrado = encriptar_cita(clave_maestra_K, motivo_final)
    if nuevo_motivo_cifrado and guardar_cita(usuario_autenticado, fecha_final, nuevo_motivo_cifrado):
        print("\n¡Cita editada con éxito!")
    else:
        print("\nError: Hubo un problema al guardar los cambios de la cita.")


def eliminar_cita(usuario_autenticado:str)-> None:
    # Pedimos la fecha de la cita a eliminar
    fecha_str = input("¿En qué fecha y hora es la cita que desea eliminar? (DD/MM/YYYY hh:mm): ")
    try:
        fecha_a_eliminar = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
    except ValueError:
        print("Formato de fecha incorrecto.")
        return
        
    # Intentamos borrar la cita
    if borrar_cita_json(usuario_autenticado, fecha_a_eliminar):
        print("\n¡Cita eliminada con éxito!")
    else:
        print("\nNo se ha encontrado ninguna cita en esa fecha o hubo un error al eliminarla.")