from datetime import datetime
import json # Para leer/escribir los datos de la cita cifrada
# Utilidades para conversión
import base64
#importamos de crypto.py algunas funciones para encriptar y desciptar las citas
from crypto import encriptar_cita,desencriptar_cita,load_citas


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
            case 1:
                ver_citas(usuario_autenticado,clave_maestra_K)
            case 2:
                crear_cita(usuario_autenticado,clave_maestra_K)
            case 3:
                editar_cita(usuario_autenticado,clave_maestra_K)
            case 4:
                eliminar_cita(usuario_autenticado,clave_maestra_K)
            case 5:
                #solo salimos del bucle cuando el usuario lo indique
                print("Que tenga un buen dia.")
                return
            case _:
                print("Porfavor introduzca un numero del 1 al 5.\n")


def ver_citas(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    '''
    Mostramos todas las citas que el usuario tenga pendientes 
    (si se le ha pasado la fecha no se muestran)
    '''
    #cargamos el json de citas    
    citas = load_citas()
    #buscamos si el usuario actual tiene citas en general
    if usuario_autenticado not in citas:
        print("No tiene citas pendientes.")
        return 
    
    #miramos si tiene citas pendientes
    n_citas = 0
    for cita in citas[usuario_autenticado].values():
        fecha_cita = desencriptar_cita(usuario_autenticado,clave_maestra_K,cita)
        if fecha_cita >= datetime.now():
            n_citas += 1
            print("Tiene una cita el",fecha_cita.strftime("%d del %m del año %Y a las %H:%M"))
    if n_citas == 0:
        print("No tiene citas pendientes.")
    elif n_citas == 1:
        print("Tiene 1 cita pendiente en total.")
    else:
        print(f"Tiene {n_citas} citas pendientes en total.")




def crear_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:

    #1.Fecha de la cita
    fecha_str = input("¿En que fecha y hora quiere la cita?(DD/MM/YYYY hh:mm):")
    fecha = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
    #La unica fecha imposible sera anterior o igual a ahora, las demas las damos como buenas
    if fecha <= datetime.now():
        print("La fecha introducida no es valida (ya ha pasado). Porfavor intentelo de nuevo.")
        return
    
    #2. Creamos y encriptamos/añadimos la cita
    encriptar_cita(usuario_autenticado,clave_maestra_K,fecha)
    

def editar_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    fecha_cita = input("¿En que fecha tiene la cita que desea editar?(DD/MM/YYYY hh:mm):")
    nueva_fecha = input("¿A que fecha desea cambiarla?(DD/MM/YYYY hh:mm):")

def eliminar_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:    
    fecha_cita = input("¿En que fecha tiene la cita que desea eliminar?(DD/MM/YYYY hh:mm):") 
