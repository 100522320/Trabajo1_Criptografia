import os
import json # Para leer/escribir los datos de la cita cifrada
from datetime import datetime

# Para el cifrado/descifrado AES-GCM (Requisitos 2 y 3)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Para manejo de errores de autenticación
from cryptography.exceptions import InvalidTag

# Utilidades para conversión
import base64

#-----------------------------
#        Configuracion 
#-----------------------------
CITAS_FILE = './jsons/citas.json'
LONGITUD_AES_NONCE = 12

def load_citas() -> dict:
    """
    Carga el diccionario de citas desde el archivo JSON.
    Devuelve un diccionario vacío si el archivo no existe o está corrupto.
    """
    try:
        with open(CITAS_FILE, 'r') as f:
            # Intenta cargar los datos del archivo
            citas = json.load(f)
            # Asegura que lo cargado sea un diccionario (manejo de archivos mal formados)
            if not isinstance(citas, dict):
                return {}
            return citas
    except (FileNotFoundError, json.JSONDecodeError):
        # Devuelve un diccionario vacío si el archivo no existe o no es JSON válido
        return {}

def guardar_cita(usuario: str, fecha: datetime, motivo_encriptado: str) -> bool:
    try:
        # Guardamos los datos de la cita
        citas = load_citas()
        if usuario not in citas:
            citas[usuario] = {}
        
        fecha_clave = fecha.isoformat()
        
        citas[usuario][fecha_clave] = motivo_encriptado
        
        with open(CITAS_FILE, 'w') as f:
            json.dump(citas, f, indent=4)
        return True
    except Exception as e:
        print(f"Error al guardar la cita: {e}")
        return False

def obtener_cita(usuario: str, fecha: datetime) -> str:
    # Busca en el JSON una cita para un usuario y fecha específicos y devuelve el motivo cifrado (string en Base64) si lo encuentra
    citas = load_citas()
    
    # Comprobamos que el usuario exista en el diccionario de citas
    if usuario in citas:
        # Convertimos la fecha a formato ISO para buscar la clave en el JSON
        fecha_clave = fecha.isoformat()
        
        # Usamos .get() para buscar la clave; devuelve None si no la encuentra
        return citas[usuario].get(fecha_clave)
        
    # Si el usuario no tiene ninguna cita, devolvemos None
    return None

def borrar_cita_json(usuario: str, fecha: datetime) -> bool:
    # Elimina una cita del archivo JSON
    try:
        citas = load_citas()
        if usuario in citas:
            fecha_clave = fecha.isoformat()
            if fecha_clave in citas[usuario]:
                del citas[usuario][fecha_clave]
                with open(CITAS_FILE, 'w') as f:
                    json.dump(citas, f, indent=4)
                return True
        return False
    except Exception as e:
        print(f"Error al eliminar la cita de la base de datos: {e}")
        return False

def encriptar_cita(clave_maestra_K:bytes, motivo_cita: str) -> str:
    try:
        # Convertimos el motivo a texto plano
        texto_plano = motivo_cita.encode('utf-8')

        # Generamos un 'nonce' aleatorio
        nonce = os.urandom(LONGITUD_AES_NONCE)

        # Ciframos el texto plano con un cifrador simétrico de bloques (AES-GCM)
        cifrador = Cipher(algorithms.AES(clave_maestra_K), modes.GCM(nonce), backend=default_backend())
        encriptador = cifrador.encryptor()
        ciphertext = encriptador.update(texto_plano) + encriptador.finalize()

        # Obtenemos el 'tag' de autenticación
        tag = encriptador.tag

        # Concatenamos nonce, tag y el texto cifrado en un único bloque de bytes para almacenarlos juntos y lo codificamos todo en Base64 
        # para convertir esos bytes en un string seguro que podemos guardar sin problemas en un archivo JSON
        motivo_encriptado = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        print("¡Cita cifrada con éxito!")
        
        return motivo_encriptado

    except Exception as e:
        print(f"Error durante el cifrado de la cita: {e}")
        return

def desencriptar_cita(clave_maestra_K: bytes, motivo_cifrado: str, fecha: datetime) -> str | None:
    try:
        # Decodificamos la cadena de texto Base64 para obtener el bloque de bytes original
        bytes_motivo_encriptado = base64.b64decode(motivo_cifrado.encode('utf-8'))

        # Separamos el nonce, que son los primeros 12 bytes
        nonce = bytes_motivo_encriptado[:LONGITUD_AES_NONCE]
        # Separamos el tag de autenticación, que son los siguientes 16 bytes
        tag = bytes_motivo_encriptado[LONGITUD_AES_NONCE:LONGITUD_AES_NONCE + 16]
        # El resto del bloque de bytes es el texto cifrado
        motivo_cifrado = bytes_motivo_encriptado[LONGITUD_AES_NONCE + 16:]

        # Configuramos el descifrador con el algoritmo (AES), la clave, y el modo GCM y le pasamos el nonce y el tag que hemos extraído
        cifrador = Cipher(algorithms.AES(clave_maestra_K), modes.GCM(nonce, tag), backend=default_backend())
        desencriptador = cifrador.decryptor()

        # Ejecutamos el descifrado. La librería verificará automáticamente si el tag es correcto
        texto_plano = desencriptador.update(motivo_cifrado) + desencriptador.finalize()
        
        # Si la verificación ha sido exitosa, convertimos los bytes del texto plano a un string, que será el motivo descifrado
        return texto_plano.decode('utf-8')

    # Si la verificación del tag falla, se captura la excepción y se informa del error
    except InvalidTag:
        print(f"¡ERROR DE AUTENTICACIÓN! La cita con fecha {fecha.strftime('%d/%m/%Y a las %H:%M')} podría haber sido manipulada.")
        return None
    # Capturamos cualquier otro posible error durante el proceso
    except Exception as e:
        print(f"Error durante el descifrado de la cita: {e}")
        return None