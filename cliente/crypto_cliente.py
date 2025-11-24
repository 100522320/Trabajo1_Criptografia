import os
from datetime import datetime
import logging # Importamos el módulo de logging

# Para el cifrado/descifrado AES-GCM (Requisitos 2 y 3)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Para manejo de errores de autenticación
from cryptography.exceptions import InvalidTag

# Para el establecimiento de la clave simétrica de comunicación con RSA
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Utilidades para conversión
import base64

# Para el manejo de errores de firma
from cryptography.exceptions import InvalidTag, InvalidSignature

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
    logger.debug("Par de claves RSA-2048 generadas para el cliente")
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

def encriptar_mensaje(clave: bytes, mensaje: str) -> str:
    """Cifra un mensaje para comunicación con el servidor (AES-GCM)"""
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
    """Descifra un mensaje recibido del servidor (AES-GCM)"""
    try:
        logger.debug(f"Intentando descifrar mensaje. Longitud mensaje cifrado: {len(mensaje_cifrado)}")
        
        datos = base64.b64decode(mensaje_cifrado.encode('utf-8'))
        logger.debug(f"Datos Base64 decodificados. Longitud: {len(datos)}")
        
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

def encriptar_cita(clave_maestra_K: bytes, motivo_cita: str) -> str:
    """
    Cifra el motivo de una cita usando AES-GCM.
    Esta es la función principal para proteger los datos sensibles (motivos de citas).
    """
    try:
        texto_plano = motivo_cita.encode('utf-8')
        nonce = os.urandom(LONGITUD_AES_NONCE)

        logger.debug(
            f"OPERACIÓN: Cifrado/MAC Generación | ALGORITMO: AES-GCM "
            f"| LONGITUD DE CLAVE: {len(clave_maestra_K) * 8} bits | NONCE: {LONGITUD_AES_NONCE} bytes."
        )

        cifrador = Cipher(algorithms.AES(clave_maestra_K), modes.GCM(nonce), backend=default_backend())
        encriptador = cifrador.encryptor()
        ciphertext = encriptador.update(texto_plano) + encriptador.finalize()
        tag = encriptador.tag

        motivo_encriptado = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        
        logger.debug(
            f"RESULTADO DEL CIFRADO/MAC: Nonce={base64.b64encode(nonce).decode('utf-8')} "
            f"| TAG={base64.b64encode(tag).decode('utf-8')} "
            f"| Cifrado: {base64.b64encode(ciphertext).decode('utf-8')}"
        )
        
        return motivo_encriptado

    except Exception as e:
        logger.error(f"Error durante el cifrado de la cita: {e}")
        return None

def desencriptar_cita(clave_maestra_K: bytes, motivo_cifrado: str, fecha: datetime) -> str | None:
    """
    Descifra el motivo de una cita usando AES-GCM.
    Verifica la integridad y autenticidad del dato mediante el tag.
    """
    try:
        bytes_motivo_encriptado = base64.b64decode(motivo_cifrado.encode('utf-8'))

        nonce = bytes_motivo_encriptado[:LONGITUD_AES_NONCE]
        tag = bytes_motivo_encriptado[LONGITUD_AES_NONCE:LONGITUD_AES_NONCE + 16]
        ciphertext = bytes_motivo_encriptado[LONGITUD_AES_NONCE + 16:]

        logger.debug(
            f"OPERACIÓN: Descifrado/MAC Verificación | ALGORITMO: AES-GCM "
            f"| LONGITUD DE CLAVE: {len(clave_maestra_K) * 8} bits | NONCE: {LONGITUD_AES_NONCE} bytes."
        )

        cifrador = Cipher(algorithms.AES(clave_maestra_K), modes.GCM(nonce, tag), backend=default_backend())
        desencriptador = cifrador.decryptor()
        texto_plano = desencriptador.update(ciphertext) + desencriptador.finalize()
        
        motivo_descifrado = texto_plano.decode('utf-8')
        logger.debug(
            f"RESULTADO DEL DESCIFRADO/MAC: Descifrado exitoso. "
            f"Texto Plano: '{motivo_descifrado}'"
        )
        
        return motivo_descifrado

    except InvalidTag:
        # Error crítico de autenticación - la cita fue manipulada
        msg = f"¡ERROR DE AUTENTICACIÓN! La cita con fecha {fecha.strftime('%d/%m/%Y a las %H:%M')} podría haber sido manipulada."
        print(msg)
        logger.error(f"FALLO CRÍTICO: InvalidTag para cita en {fecha.isoformat()}. Datos posiblemente manipulados.")
        return None
    except Exception as e:
        logger.error(f"Error durante el descifrado de la cita: {e}")
        return None
    
def generar_firma(clave_privada, mensaje: str) -> str:
    """
    Genera una firma digital para el mensaje usando la clave privada RSA.
    Utiliza el esquema PSS con SHA256.
    """
    try:
        mensaje_bytes = mensaje.encode('utf-8')
        
        # 1. Firmar usando el método directo .sign() (solución al error 'no attribute signer')
        firma = clave_privada.sign(
            mensaje_bytes,
            padding.PSS( # <--- Esquema PSS
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH 
            ),
            hashes.SHA256() # <--- Función de Hash (SHA256)
        )
        
        firma_b64 = base64.b64encode(firma).decode('utf-8')
        
        logger.debug(
            f"OPERACIÓN: Firma Digital Generación | ALGORITMO: RSA-PSS (SHA256) "
            f"| LONGITUD DE CLAVE: {clave_privada.key_size} bits | LONGITUD DE FIRMA: {len(firma)} bytes."
        )
        logger.debug(f"RESULTADO DE LA FIRMA (B64): {firma_b64[:30]}...")
        
        return firma_b64
        
    except Exception as e:
        logger.error(f"Error durante la generación de la firma digital: {e}")
        return None

def verificar_firma(clave_publica, mensaje: str, firma_b64: str) -> bool:
    """
    Verifica una firma digital para un mensaje dado usando la clave pública RSA.
    """
    try:
        firma = base64.b64decode(firma_b64.encode('utf-8'))
        mensaje_bytes = mensaje.encode('utf-8')
        
        # 1. Verificar la firma usando el método directo .verify()
        clave_publica.verify(
            firma,
            mensaje_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        logger.info(
            f"OPERACIÓN: Firma Digital Verificación | ALGORITMO: RSA-PSS (SHA256) | RESULTADO: ÉXITO (Válida)"
        )
        return True
        
    except InvalidSignature:
        # ... (Resto del manejo de error)
        return False
    except Exception as e:
        logger.error(f"Error durante la verificación de la firma digital: {e}")
        return False