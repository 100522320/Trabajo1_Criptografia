import os
from datetime import datetime, timezone
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

# Para la lectura de certificados
from cryptography import x509

# Obtener el logger configurado en main.py
logger = logging.getLogger('SecureCitasCLI')

#-----------------------------
#        Configuracion 
#-----------------------------
LONGITUD_AES_NONCE = 12

def cargar_cadena_certificacion(ruta_ac1='certificados_AC/ac1cert.pem', ruta_ac2='certificados_AC/ac2cert.pem'):
    """
    Carga los certificados de la cadena de certificación
    """
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Cargar AC1 (raíz)
        ruta_completa_ac1 = os.path.join(current_dir, ruta_ac1)
        with open(ruta_completa_ac1, 'rb') as f:
            cert_ac1 = x509.load_pem_x509_certificate(f.read())
        logger.info(f"Certificado de AC1 (raíz) cargado desde {ruta_ac1}")
        
        # Cargar AC2 (intermedia)
        ruta_completa_ac2 = os.path.join(current_dir, ruta_ac2)
        with open(ruta_completa_ac2, 'rb') as f:
            cert_ac2 = x509.load_pem_x509_certificate(f.read())
        logger.info(f"Certificado de AC2 (subordinada) cargado desde {ruta_ac2}")
        
        logger.info("Cadena de confianza cargada correctamente (AC1 y AC2)")
        return cert_ac1, cert_ac2
    except FileNotFoundError as e:
        logger.error(f"No se encontró el archivo de certificado: {e}")
        return None, None
    except Exception as e:
        logger.error(f"Error cargando cadena de confianza: {e}")
        return None, None

def verificar_certificado(cert_servidor_pem, cert_ac1, cert_ac2, index_cert_ac2):
    """
    Verifica el certificado del servidor usando la cadena de certificación
    
    Pasos de la validación de la cadena de certificación:
    1. Verificar que AC1 es autofirmado (raíz confiable)
    2. Verificar que AC2 está firmado por AC1
    3. Verificar que el certificado del servidor está firmado por AC2
    4. Verificar fechas de validez
    5. Verificar que el certificado del servidor sea válido (que no haya sido revocado)
    """
    try:
        # Cargar certificado del servidor
        cert_servidor = x509.load_pem_x509_certificate(cert_servidor_pem)
        
        logger.info("=" * 60)
        logger.info("INICIANDO VERIFICACIÓN DE CERTIFICADO DEL SERVIDOR")
        logger.info("=" * 60)
        logger.info(f"Dueño del certificado: {cert_servidor.subject}")
        logger.info(f"Emisor del certificado: {cert_servidor.issuer}")
        
        # 1. Verificar que AC1 es autofirmado (raíz)
        logger.info("\nVerificando AC1 (raíz autofirmada)...")
        try:
            clave_publica_ac1 = cert_ac1.public_key()
            clave_publica_ac1.verify(
                cert_ac1.signature,
                cert_ac1.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_ac1.signature_hash_algorithm
            )
            logger.info("✓ AC1 verificado como certificado raíz autofirmado")
        except Exception as e:
            logger.error(f"✗ AC1 no es un certificado raíz válido: {e}")
            return False, None
        
        # 2. Verificar que AC2 está firmado por AC1
        logger.info("\nVerificando AC2 (firmada por AC1)...")
        try:
            clave_publica_ac1.verify(
                cert_ac2.signature,
                cert_ac2.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_ac2.signature_hash_algorithm
            )
            logger.info("✓ AC2 verificada correctamente (firmada por AC1)")
        except Exception as e:
            logger.error(f"✗ AC2 no está firmada correctamente por AC1: {e}")
            return False, None
        
        # 3. Verificar que el certificado del servidor está firmado por AC2
        logger.info("\nVerificando certificado del servidor (firmado por AC2)...")
        try:
            clave_publica_ac2 = cert_ac2.public_key()
            clave_publica_ac2.verify(
                cert_servidor.signature,
                cert_servidor.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_servidor.signature_hash_algorithm
            )
            logger.info("✓ Certificado del servidor verificado (firmado por AC2)")
        except Exception as e:
            logger.error(f"✗ Certificado del servidor no está firmado por AC2: {e}")
            return False, None
        
        # 4. Verificar fechas de validez
        logger.info("\nVerificando fechas de validez...")
        ahora = datetime.now(timezone.utc)
        
        logger.info(f"Válido desde: {cert_servidor.not_valid_before_utc}")
        logger.info(f"Válido hasta: {cert_servidor.not_valid_after_utc}")
        logger.info(f"Fecha actual: {ahora}")
        
        if ahora < cert_servidor.not_valid_before_utc:
            logger.error("✗ El certificado aún no es válido")
            return False, None
        
        if ahora > cert_servidor.not_valid_after_utc:
            logger.error("✗ El certificado ha expirado")
            return False, None
        
        logger.info("✓ Fechas de validez correctas")

        # 5. Verificar estado del certificado
        logger.info("\nVerificando estado del certificado...")
        for linea in index_cert_ac2:
            if "CN=22125_22320" in linea:
                if linea.split()[0] != "V":
                    logger.error("✗ El certificado ha sido revocado")
                    return False, None
        logger.info("✓ Estado del certificado válido")
        
        # Extraer clave pública del certificado verificado
        clave_publica_servidor = cert_servidor.public_key()
        
        logger.info("=" * 60)
        logger.info("✓ CERTIFICADO DEL SERVIDOR VERIFICADO EXITOSAMENTE")
        logger.info("=" * 60)
        
        return True, clave_publica_servidor
        
    except Exception as e:
        logger.error(f"Error durante la verificación del certificado: {e}")
        return False, None

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
        return False
    except Exception as e:
        logger.error(f"Error durante la verificación de la firma digital: {e}")
        return False