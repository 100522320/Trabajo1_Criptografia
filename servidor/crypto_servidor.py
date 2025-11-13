import os
import json # Para leer/escribir los datos de la cita cifrada
from datetime import datetime
import logging # Importamos el módulo de logging

# Para el cifrado/descifrado AES-GCM (Requisitos 2 y 3)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Para manejo de errores de autenticación
from cryptography.exceptions import InvalidTag

# Utilidades para conversión
import base64

# Obtener el logger configurado en main.py
logger = logging.getLogger('SecureCitasCLI')

#-----------------------------
#        Configuracion 
#-----------------------------
# Obtenemos el directorio donde está este archivo
current_dir = os.path.dirname(os.path.abspath(__file__))
# Construimos la ruta al archivo de usuarios
CITAS_FILE = os.path.join(current_dir, 'jsons', 'citas.json')
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
                logger.warning(f"Archivo {CITAS_FILE} corrupto o no es un diccionario.")
                return {}
            return citas
    except (FileNotFoundError, json.JSONDecodeError):
        # Devuelve un diccionario vacío si el archivo no existe o no es JSON válido
        logger.warning(f"Archivo de citas no encontrado o JSON inválido: {CITAS_FILE}. Creando uno nuevo.")
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
        logger.info(f"Cita guardada para {usuario} en {fecha_clave}. Datos cifrados en JSON.")
        return True
    except Exception as e:
        logger.error(f"Error al guardar la cita: {e}")
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
                logger.info(f"Cita de {usuario} en {fecha_clave} eliminada del JSON.")
                return True
        logger.warning(f"Intento de eliminar cita de {usuario} en {fecha.isoformat()} fallido (no encontrada).")
        return False
    except Exception as e:
        logger.error(f"Error al eliminar la cita de la base de datos: {e}")
        return False

def encriptar_cita(clave_maestra_K:bytes, motivo_cita: str) -> str:
    # Requisitos 2 (Cifrado) y 3 (Etiqueta de Autenticación)
    try:
        # Convertimos el motivo a texto plano
        texto_plano = motivo_cita.encode('utf-8')

        # Generamos un 'nonce' aleatorio
        nonce = os.urandom(LONGITUD_AES_NONCE)

        # Mensaje de depuración con el algoritmo y la longitud de clave
        logger.debug(
            f"OPERACIÓN: Cifrado/MAC Generación | ALGORITMO: AES-GCM "
            f"| LONGITUD DE CLAVE: {len(clave_maestra_K) * 8} bits | NONCE: {LONGITUD_AES_NONCE} bytes."
        )

        # Ciframos el texto plano con un cifrador simétrico de bloques (AES-GCM)
        cifrador = Cipher(algorithms.AES(clave_maestra_K), modes.GCM(nonce), backend=default_backend())
        encriptador = cifrador.encryptor()
        ciphertext = encriptador.update(texto_plano) + encriptador.finalize()

        # Obtenemos el 'tag' de autenticación
        tag = encriptador.tag

        # Concatenamos nonce, tag y el texto cifrado en un único bloque de bytes para almacenarlos juntos y lo codificamos todo en Base64 
        # para convertir esos bytes en un string seguro que podemos guardar sin problemas en un archivo JSON
        motivo_encriptado = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        
        # Mensaje de depuración con el resultado (el texto cifrado/etiqueta)
        logger.debug(
            f"RESULTADO DEL CIFRADO/MAC: Nonce={base64.b64encode(nonce).decode('utf-8')} "
            f"| TAG={base64.b64encode(tag).decode('utf-8')} "
            f"| Cifrado : {base64.b64encode(ciphertext).decode('utf-8')}"
        )
        
        return motivo_encriptado

    except Exception as e:
        logger.error(f"Error durante el cifrado de la cita: {e}")
        return

def desencriptar_cita(clave_maestra_K: bytes, motivo_cifrado: str, fecha: datetime) -> str | None:
    # Requisitos 2 (Descifrado) y 3 (Verificación de Etiqueta de Autenticación)
    try:
        # Decodificamos la cadena de texto Base64 para obtener el bloque de bytes original
        bytes_motivo_encriptado = base64.b64decode(motivo_cifrado.encode('utf-8'))

        # Separamos el nonce, que son los primeros 12 bytes
        nonce = bytes_motivo_encriptado[:LONGITUD_AES_NONCE]
        # Separamos el tag de autenticación, que son los siguientes 16 bytes
        tag = bytes_motivo_encriptado[LONGITUD_AES_NONCE:LONGITUD_AES_NONCE + 16]
        # El resto del bloque de bytes es el texto cifrado
        ciphertext = bytes_motivo_encriptado[LONGITUD_AES_NONCE + 16:]

        # Mensaje de depuración con el algoritmo y la longitud de clave
        logger.debug(
            f"OPERACIÓN: Descifrado/MAC Verificación | ALGORITMO: AES-GCM "
            f"| LONGITUD DE CLAVE: {len(clave_maestra_K) * 8} bits | NONCE: {LONGITUD_AES_NONCE} bytes."
        )

        # Configuramos el descifrador con el algoritmo (AES), la clave, y el modo GCM y le pasamos el nonce y el tag que hemos extraído
        cifrador = Cipher(algorithms.AES(clave_maestra_K), modes.GCM(nonce, tag), backend=default_backend())
        desencriptador = cifrador.decryptor()

        # Ejecutamos el descifrado. La librería verificará automáticamente si el tag es correcto
        texto_plano = desencriptador.update(ciphertext) + desencriptador.finalize()
        
        # Mensaje de depuración con el resultado (el texto plano descifrado)
        motivo_descifrado = texto_plano.decode('utf-8')
        logger.debug(
            f"RESULTADO DEL DESCIFRADO/MAC: Descifrado exitoso. "
            f"Texto Plano: '{motivo_descifrado}'"
        )
        
        return motivo_descifrado

    # Si la verificación del tag falla, se captura la excepción y se informa del error
    except InvalidTag:
        # Requisito 3: Error de autenticación
        msg = f"¡ERROR DE AUTENTICACIÓN! La cita con fecha {fecha.strftime('%d/%m/%Y a las %H:%M')} podría haber sido manipulada."
        print(msg)
        logger.error(f"FALLO CRÍTICO: InvalidTag para cita en {fecha.isoformat()}. Datos posiblemente manipulados.")
        return None
    # Capturamos cualquier otro posible error durante el proceso
    except Exception as e:
        logger.error(f"Error durante el descifrado de la cita: {e}")
        return None