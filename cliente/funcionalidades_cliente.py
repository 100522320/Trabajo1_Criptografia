from datetime import datetime
import os
import json # Para leer/escribir los datos de la cita cifrada
import logging # AÑADIDO: Importamos el módulo de logging
# Utilidades para conversión
import base64
# Utilidades para la conexión
import socket
# Importamos de crypto.py las funciones relacionadas con la seeguridad
from crypto_cliente import (
    encriptar_cita, desencriptar_cita, encriptar_mensaje, desencriptar_mensaje,
    generar_par_claves, serializar_clave_publica, deserializar_clave_publica,
    encriptar_asimetrico, desencriptar_asimetrico
)

# AÑADIDO: Obtener el logger configurado en main.py
logger = logging.getLogger('SecureCitasCLI')

class ClienteAPI:
    def __init__(self):
        self.host = 'localhost'
        self.port = 5000
        self.clave_comunicacion = None
        self.clave_privada = None
        self.clave_publica_servidor = None
        self.socket = None  # Socket persistente
        
    def establecer_claves(self, clave_privada, clave_publica_servidor):
        self.clave_privada = clave_privada
        self.clave_publica_servidor = clave_publica_servidor
        
    def establecer_clave_comunicacion(self, clave: bytes):
        self.clave_comunicacion = clave
        
    def conectar(self):
        """Establece una conexión persistente con el servidor"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            logger.info("Conexión establecida con el servidor")
            return True
        except Exception as e:
            logger.error(f"Error al conectar: {e}")
            return False
    
    def desconectar(self):
        """Cierra la conexión con el servidor"""
        if self.socket:
            try:
                self.socket.close()
                logger.info("Conexión cerrada")
            except:
                pass
            self.socket = None
        
    def negociar_clave_segura(self):
        """Negocia una clave de comunicación segura usando cifrado asimétrico"""
        try:
            # Conectar al servidor
            if not self.conectar():
                return False
            
            # 1. Cliente genera par de claves
            self.clave_privada, clave_publica_cliente = generar_par_claves()
            clave_publica_cliente_bytes = serializar_clave_publica(clave_publica_cliente)
            
            # 2. Enviar clave pública al servidor
            logger.info("Enviando clave pública al servidor...")
            self.socket.send(b"INICIAR_NEGOCIACION|" + clave_publica_cliente_bytes)
            
            # 3. Recibir clave pública del servidor
            respuesta = self.socket.recv(4096)
            logger.debug(f"Respuesta recibida: {respuesta[:100]}...")
            
            if b"CLAVE_PUBLICA_SERVIDOR|" in respuesta:
                partes = respuesta.split(b"|", 1)
                clave_publica_servidor_bytes = partes[1]
                self.clave_publica_servidor = deserializar_clave_publica(clave_publica_servidor_bytes)
                logger.info("Clave pública del servidor recibida")
                
                # 4. Generar y enviar clave de sesión cifrada
                clave_sesion = os.urandom(32)  # 256 bits para AES
                logger.info(f"Clave de sesión generada: {len(clave_sesion)} bytes")
                
                clave_sesion_cifrada = encriptar_asimetrico(
                    self.clave_publica_servidor, 
                    base64.b64encode(clave_sesion).decode('utf-8')
                )
                
                if clave_sesion_cifrada:
                    logger.info("Enviando clave de sesión cifrada...")
                    self.socket.send(f"CLAVE_SESION_CIFRADA|{clave_sesion_cifrada}".encode('utf-8'))
                    
                    # 5. Recibir confirmación
                    confirmacion = self.socket.recv(1024).decode('utf-8')
                    logger.info(f"Confirmación recibida: {confirmacion}")
                    
                    if confirmacion == "NEGOCIACION_EXITOSA":
                        self.establecer_clave_comunicacion(clave_sesion)
                        logger.info("Negociación exitosa - canal seguro establecido")
                        return True
                    else:
                        logger.error(f"Confirmación inesperada: {confirmacion}")
                else:
                    logger.error("Error al cifrar clave de sesión")
            else:
                logger.error("Respuesta del servidor no contiene clave pública")
            
            return False
            
        except Exception as e:
            logger.error(f"Error en negociación de clave: {e}")
            self.desconectar()
            return False
        
    def enviar_comando(self, comando):
        """Envía un comando a través del socket persistente"""
        try:
            if not self.socket:
                logger.error("No hay conexión establecida")
                return "ERROR: Sin conexión"
            
            if self.clave_comunicacion:
                # Comunicación cifrada con clave de sesión
                logger.debug(f"Cifrando comando: {comando}")
                comando_cifrado = encriptar_mensaje(self.clave_comunicacion, comando)
                
                if not comando_cifrado:
                    logger.error("Error al cifrar comando")
                    return "ERROR_CIFRADO"
                
                logger.debug(f"Enviando comando cifrado (longitud: {len(comando_cifrado)})")
                self.socket.send(comando_cifrado.encode('utf-8'))
                
                # Recibir respuesta
                logger.debug("Esperando respuesta del servidor...")
                respuesta_cifrada = self.socket.recv(4096).decode('utf-8')
                logger.debug(f"Respuesta cifrada recibida (longitud: {len(respuesta_cifrada)})")
                
                if not respuesta_cifrada:
                    logger.error("Respuesta vacía del servidor")
                    return "ERROR: Respuesta vacía"
                
                respuesta = desencriptar_mensaje(self.clave_comunicacion, respuesta_cifrada)
                
                if not respuesta:
                    logger.error("Error al descifrar respuesta")
                    return "ERROR_DESCIFRADO"
                
                logger.debug(f"Respuesta descifrada: {respuesta}")
                return respuesta
            else:
                logger.error("No hay clave de comunicación establecida")
                return "ERROR: Sin clave de comunicación"
                
        except ConnectionRefusedError:
            logger.error("Servidor no disponible")
            return "ERROR: Servidor no disponible"
        except Exception as e:
            logger.error(f"Error al enviar comando: {e}")
            return f"ERROR: {str(e)}"

def registrar_usuario(nombre_usuario: str, contraseña: str) -> bool:
    """Registra un usuario mediante comunicación segura"""
    api = ClienteAPI()
    
    try:
        # Primero negociar clave segura
        if not api.negociar_clave_segura():
            logger.error("Fallo en negociación para registro")
            return False
            
        # Ahora enviar registro cifrado
        respuesta = api.enviar_comando(f"REGISTRO|{nombre_usuario}|{contraseña}")
        return respuesta == "REGISTRO_EXITOSO"
    finally:
        api.desconectar()

def autenticar_usuario(nombre_usuario: str, contraseña: str) -> bool:
    """Autentica un usuario mediante comunicación segura"""
    api = ClienteAPI()
    
    try:
        # Primero negociar clave segura
        if not api.negociar_clave_segura():
            logger.error("Fallo en negociación para login")
            return False
            
        respuesta = api.enviar_comando(f"LOGIN|{nombre_usuario}|{contraseña}")
        return respuesta == "LOGIN_EXITOSO"
    finally:
        api.desconectar()

def derivar_clave(contraseña_maestra: str, usuario_autenticado: str) -> bytes | None:
    """
    Deriva la Clave Maestra de Cifrado (K) para el usuario autenticado
    a partir de su contraseña y el salt almacenado, usando PBKDF2HMAC.
    """
    api = ClienteAPI()
    
    try:
        # PRIMERO negociar clave segura
        logger.info("Negociando clave segura con el servidor...")
        if not api.negociar_clave_segura():
            logger.error("Fallo en la negociación de clave segura")
            return None
        
        # LUEGO pedir la derivación de clave a través del canal seguro
        logger.info(f"Solicitando derivación de clave para {usuario_autenticado}")
        respuesta = api.enviar_comando(f"DERIVAR_CLAVE|{usuario_autenticado}|{contraseña_maestra}")
        
        if respuesta.startswith("CLAVE_CITAS|"):
            clave_citas_b64 = respuesta.split("|")[1]
            try:
                clave_K = base64.b64decode(clave_citas_b64)
                logger.info(f"Éxito: Clave Maestra K recibida del servidor.")
                return clave_K
            except Exception as e:
                logger.error(f"Error al decodificar la clave del servidor: {e}")
                return None
        
        logger.error(f"Error derivando clave: {respuesta}")
        return None
    finally:
        api.desconectar()

def obtener_citas_usuario(usuario: str, clave_comunicacion: bytes) -> dict:
    """Obtiene todas las citas del usuario desde el servidor"""
    api = ClienteAPI()
    
    try:
        if not api.negociar_clave_segura():
            return {}
        
        # NO sobrescribir la clave de sesión - ya está establecida por negociar_clave_segura()
        respuesta = api.enviar_comando(f"OBTENER_CITAS|{usuario}")
        
        try:
            return json.loads(respuesta) if respuesta and respuesta not in ["ERROR: Servidor no disponible", "ERROR_CIFRADO", "ERROR_DESCIFRADO"] else {}
        except:
            return {}
    finally:
        api.desconectar()

def guardar_cita_servidor(usuario: str, fecha: datetime, motivo_cifrado: str, clave_comunicacion: bytes) -> bool:
    """Guarda una cita en el servidor"""
    api = ClienteAPI()
    
    try:
        if not api.negociar_clave_segura():
            return False
        
        # NO sobrescribir la clave de sesión - ya está establecida por negociar_clave_segura()
        fecha_iso = fecha.isoformat()
        respuesta = api.enviar_comando(f"GUARDAR_CITA|{usuario}|{fecha_iso}|{motivo_cifrado}")
        return respuesta == "CITA_GUARDADA"
    finally:
        api.desconectar()

def obtener_cita_servidor(usuario: str, fecha: datetime, clave_comunicacion: bytes) -> str:
    """Obtiene una cita específica del servidor"""
    api = ClienteAPI()
    
    try:
        if not api.negociar_clave_segura():
            return None
        
        # NO sobrescribir la clave de sesión - ya está establecida por negociar_clave_segura()
        fecha_iso = fecha.isoformat()
        respuesta = api.enviar_comando(f"OBTENER_CITA|{usuario}|{fecha_iso}")
        return respuesta if respuesta != "CITA_NO_ENCONTRADA" else None
    finally:
        api.desconectar()

def borrar_cita_servidor(usuario: str, fecha: datetime, clave_comunicacion: bytes) -> bool:
    """Elimina una cita del servidor"""
    api = ClienteAPI()
    
    try:
        if not api.negociar_clave_segura():
            return False
        
        # NO sobrescribir la clave de sesión - ya está establecida por negociar_clave_segura()
        fecha_iso = fecha.isoformat()
        respuesta = api.enviar_comando(f"BORRAR_CITA|{usuario}|{fecha_iso}")
        return respuesta == "CITA_BORRADA"
    finally:
        api.desconectar()

# [El resto de funciones permanecen igual: aplicacion, ver_citas_pendientes, crear_cita, editar_cita, eliminar_cita]

def aplicacion(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    """
    Se encarga de dar funcionalidades a la aplicacion:
    Ver citas, editarlas, crearlas y borrarlas.
    """

    while True:
        print("\nCosas que puede hacer:")
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
                eliminar_cita(usuario_autenticado, clave_maestra_K)
            case '5':
                logger.info("El usuario ha salido de la aplicación.")
                print("Que tenga un buen dia.")
                return
            case _:
                print("Porfavor introduzca un numero del 1 al 5.\n")

def ver_citas_pendientes(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    '''
    Mostramos todas las citas que el usuario tenga pendientes
    (si se le ha pasado la fecha no se muestran)
    '''
    citas = obtener_citas_usuario(usuario_autenticado, clave_maestra_K)
    if not citas:
        logger.info(f"Usuario {usuario_autenticado} no tiene citas guardadas.")
        print("\nNo tiene ninguna cita guardada.")
        return

    citas_pendientes = []
    print("\n--- TUS CITAS PENDIENTES ---")

    for fecha_str, motivo_cifrado in citas.items():
        fecha_cita = datetime.fromisoformat(fecha_str)
        if fecha_cita >= datetime.now():
            motivo_descifrado = desencriptar_cita(clave_maestra_K, motivo_cifrado, fecha_cita)
            if motivo_descifrado:
                citas_pendientes.append((fecha_cita, motivo_descifrado))
            else:
                citas_pendientes.append((fecha_cita, "[ERROR AL LEER MOTIVO]"))

    if not citas_pendientes:
        logger.info(f"Usuario {usuario_autenticado} no tiene citas pendientes.")
        print("No tiene citas pendientes.")
        return

    citas_pendientes.sort(key=lambda item: item[0])

    for i, (fecha, motivo) in enumerate(citas_pendientes):
        print(f"{i+1}. {fecha.strftime('%d/%m/%Y a las %H:%M')} -> {motivo}")

    print(f"\nTotal: {len(citas_pendientes)} cita(s) pendiente(s).")

def crear_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    fecha_str = input("¿En que fecha y hora quiere la cita?(DD/MM/YYYY hh:mm):")
    
    try:
        fecha = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
    except ValueError:
        logger.warning("Error de formato de fecha en creación de cita.")
        print("\nError: El formato de la fecha no es correcto. Use DD/MM/YYYY hh:mm.")
        return

    if fecha <= datetime.now():
        logger.warning(f"Intento de crear cita en fecha pasada: {fecha.isoformat()}")
        print("La fecha introducida no es valida (ya ha pasado). Porfavor intentelo de nuevo.")
        return
    
    motivo = input("Introduzca el motivo de la cita: ").strip()
    if not motivo:
        logger.warning("Intento de crear cita con motivo vacío.")
        print("El motivo no puede estar vacío.")
        return
    
    motivo_cifrado = encriptar_cita(clave_maestra_K, motivo)
    if motivo_cifrado:
        if guardar_cita_servidor(usuario_autenticado, fecha, motivo_cifrado, clave_maestra_K):
            print("\n¡Cita guardada con éxito!")
        else:
            print("\nError: No se pudo guardar la cita en el servidor.")
    else:
        logger.error(f"Fallo al cifrar la cita para {usuario_autenticado}.")
        print("\nError: No se pudo cifrar la cita.")

def editar_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    fecha_str = input("¿Qué fecha y hora tiene la cita que desea editar? (DD/MM/YYYY hh:mm): ")
    try:
        fecha_antigua = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
    except ValueError:
        logger.warning("Formato de fecha antigua incorrecto.")
        print("Formato de fecha incorrecto.")
        return
    
    motivo_cifrado_antiguo = obtener_cita_servidor(usuario_autenticado, fecha_antigua, clave_maestra_K)
    if motivo_cifrado_antiguo is None:
        logger.warning(f"Intento de editar cita no encontrada para {usuario_autenticado} en {fecha_antigua.isoformat()}")
        print("No se ha encontrado ninguna cita en esa fecha.")
        return
        
    print("--- Introduzca los nuevos datos de la cita ---")
    nueva_fecha_str = input("Nueva fecha y hora (dejar en blanco para no cambiar): ").strip()
    nuevo_motivo = input("Nuevo motivo (dejar en blanco para no cambiar): ").strip()

    if not nueva_fecha_str and not nuevo_motivo:
        print("No se ha realizado ningún cambio.")
        return
        
    fecha_final = fecha_antigua
    if nueva_fecha_str:
        try:
            fecha_final = datetime.strptime(nueva_fecha_str, "%d/%m/%Y %H:%M")
        except ValueError:
            logger.warning("Formato de nueva fecha incorrecto.")
            print("Formato de nueva fecha incorrecto. Se cancela la edición.")
            return
    
    if not borrar_cita_servidor(usuario_autenticado, fecha_antigua, clave_maestra_K):
        logger.error("Error crítico al intentar eliminar la cita antigua para edición.")
        print("Error: No se pudo eliminar la cita antigua para actualizarla.")
        return

    motivo_final = nuevo_motivo
    if not nuevo_motivo:
        motivo_final = desencriptar_cita(clave_maestra_K, motivo_cifrado_antiguo, fecha_final)
        if motivo_final is None:
            logger.error("Fallo al descifrar el motivo original durante la edición.")
            print("\nError: No se pudo leer el motivo original de la cita. Edición cancelada.")
            return
    
    nuevo_motivo_cifrado = encriptar_cita(clave_maestra_K, motivo_final)
    if nuevo_motivo_cifrado and guardar_cita_servidor(usuario_autenticado, fecha_final, nuevo_motivo_cifrado, clave_maestra_K):
        print("\n¡Cita editada con éxito!")
        logger.info(f"Cita editada con éxito para {usuario_autenticado}.")
    else:
        logger.error(f"Fallo al guardar los cambios de la cita para {usuario_autenticado}.")
        print("\nError: Hubo un problema al guardar los cambios de la cita.")

def eliminar_cita(usuario_autenticado:str, clave_maestra_K: bytes)-> None:
    fecha_str = input("¿En qué fecha y hora es la cita que desea eliminar? (DD/MM/YYYY hh:mm): ")
    try:
        fecha_a_eliminar = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
    except ValueError:
        logger.warning("Formato de fecha incorrecto para eliminación.")
        print("Formato de fecha incorrecto.")
        return
        
    if borrar_cita_servidor(usuario_autenticado, fecha_a_eliminar, clave_maestra_K):
        print("\n¡Cita eliminada con éxito!")
        logger.info(f"Cita eliminada exitosamente para {usuario_autenticado} en {fecha_a_eliminar.isoformat()}.")
    else:
        print("\nNo se ha encontrado ninguna cita en esa fecha o hubo un error al eliminarla.")