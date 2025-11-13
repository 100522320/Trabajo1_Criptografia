import os
import json # Para leer/escribir los datos de la cita cifrada
from datetime import datetime
import logging # Importamos el módulo de logging

# Para el cifrado/descifrado AES-GCM (Requisitos 2 y 3)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Para manejo de errores de autenticación
from cryptography.exceptions import InvalidTag

# Para el establecimineto de la clave simétrica de comunicación
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Utilidades para conversión
import base64

# Obtener el logger configurado en main.py
logger = logging.getLogger('SecureCitasCLI')

#-----------------------------
#        Configuracion 
#-----------------------------
LONGITUD_AES_NONCE = 12

def generar_par_claves():
    """Genera un par de claves RSA para el cliente"""
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def serializar_clave_publica(clave_publica):
    """Serializa una clave pública RSA a formato PEM"""
    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserializar_clave_publica(clave_publica_bytes):
    """Deserializa una clave pública RSA desde formato PEM"""
    return serialization.load_pem_public_key(clave_publica_bytes)

def encriptar_asimetrico(clave_publica, mensaje: str) -> str:
    """Cifra un mensaje usando RSA con la clave pública del servidor"""
    try:
        mensaje_cifrado = clave_publica.encrypt(
            mensaje.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(mensaje_cifrado).decode('utf-8')
    except Exception as e:
        logger.error(f"Error durante el cifrado asimétrico: {e}")
        return None

def desencriptar_asimetrico(clave_privada, mensaje_cifrado: str) -> str:
    """Descifra un mensaje usando RSA con la clave privada del cliente"""
    try:
        mensaje_bytes = base64.b64decode(mensaje_cifrado.encode('utf-8'))
        mensaje_descifrado = clave_privada.decrypt(
            mensaje_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return mensaje_descifrado.decode('utf-8')
    except Exception as e:
        logger.error(f"Error durante el descifrado asimétrico: {e}")
        return None

def encriptar_mensaje(clave: bytes, mensaje: str) -> str:
    """Cifra un mensaje para comunicación segura con el servidor"""
    try:
        nonce = os.urandom(LONGITUD_AES_NONCE)
        cifrador = Cipher(algorithms.AES(clave), modes.GCM(nonce), backend=default_backend())
        encriptador = cifrador.encryptor()
        texto_cifrado = encriptador.update(mensaje.encode('utf-8')) + encriptador.finalize()
        tag = encriptador.tag
        return base64.b64encode(nonce + tag + texto_cifrado).decode('utf-8')
    except Exception as e:
        logger.error(f"Error durante el cifrado del mensaje: {e}")
        return None

def desencriptar_mensaje(clave: bytes, mensaje_cifrado: str) -> str:
    """Descifra un mensaje recibido del servidor"""
    try:
        logger.debug(f"Intentando descifrar mensaje. Longitud mensaje cifrado: {len(mensaje_cifrado)}")
        
        datos = base64.b64decode(mensaje_cifrado.encode('utf-8'))
        logger.debug(f"Datos Base64 decodificados. Longitud: {len(datos)}")
        
        # Verificar que tenemos suficientes datos
        if len(datos) < LONGITUD_AES_NONCE + 16:
            logger.error(f"Datos insuficientes. Se esperaban al menos {LONGITUD_AES_NONCE + 16} bytes, se recibieron {len(datos)}")
            return None
            
        nonce = datos[:LONGITUD_AES_NONCE]
        tag = datos[LONGITUD_AES_NONCE:LONGITUD_AES_NONCE + 16]
        texto_cifrado = datos[LONGITUD_AES_NONCE + 16:]
        
        logger.debug(f"Nonce: {len(nonce)} bytes, Tag: {len(tag)} bytes, Texto cifrado: {len(texto_cifrado)} bytes")
        
        cifrador = Cipher(algorithms.AES(clave), modes.GCM(nonce, tag), backend=default_backend())
        desencriptador = cifrador.decryptor()
        texto_plano = desencriptador.update(texto_cifrado) + desencriptador.finalize()
        
        logger.debug("Descifrado exitoso")
        return texto_plano.decode('utf-8')
        
    except InvalidTag:
        logger.error("FALLO CRÍTICO: InvalidTag en mensaje del servidor. Datos posiblemente manipulados.")
        return None
    except Exception as e:
        logger.error(f"Error durante el descifrado del mensaje: {e}")
        return None

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