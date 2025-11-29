from datetime import datetime
import os
import json # Para leer/escribir los datos de la cita cifrada
import logging # AÑADIDO: Importamos el módulo de logging
# Utilidades para conversión
import base64
# Utilidades para la conexión y el protocolo TLS
import socket
import ssl
# Importamos de crypto.py las funciones relacionadas con la seeguridad
from crypto_cliente import (
    encriptar_cita, desencriptar_cita, encriptar_mensaje, desencriptar_mensaje,
    generar_par_claves, serializar_clave_publica, encriptar_asimetrico, verificar_firma, 
    cargar_cadena_certificacion, verificar_certificado
)

# AÑADIDO: Obtener el logger configurado en main.py
logger = logging.getLogger('SecureCitasCLI')

# Instancia global del cliente para mantener la conexión
_cliente_global = None

class ClienteAPI:
    def __init__(self):
        self.host = 'localhost'
        self.port = 5000
        self.clave_comunicacion = None
        self.clave_privada = None
        self.clave_publica_servidor = None
        self.socket = None
        self.conectado = False
        
    def establecer_clave_comunicacion(self, clave: bytes):
        self.clave_comunicacion = clave
        
    def conectar(self):
        """Establece una conexión TCP con el servidor"""
        try:
            if self.socket:
                try:
                    self.socket.setblocking(False)
                    data = self.socket.recv(1, socket.MSG_PEEK)
                    self.socket.setblocking(True)
                    if not data:
                        logger.info("Conexión cerrada, reconectando...")
                        self.socket.close()
                        self.socket = None
                        self.conectado = False
                except BlockingIOError:
                    self.socket.setblocking(True)
                    return True
                except:
                    logger.info("Error en conexión, reconectando...")
                    try:
                        self.socket.close()
                    except:
                        pass
                    self.socket = None
                    self.conectado = False
            
            # Crear socket TCP normal
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.conectado = True
            logger.info("Conexión establecida con el servidor")
            return True
            
        except Exception as e:
            logger.error(f"Error al conectar: {e}")
            self.conectado = False
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
            self.conectado = False
        
    def negociar_clave_segura(self):
        """Negocia una clave de comunicación segura usando cifrado híbrido RSA+AES"""
        try:
            if not self.conectar():
                return False
            
            # 1. Cliente genera par de claves RSA
            self.clave_privada, clave_publica_cliente = generar_par_claves()
            clave_publica_cliente_bytes = serializar_clave_publica(clave_publica_cliente)
            
            # 2. Enviar clave pública al servidor
            logger.info("Enviando clave pública al servidor...")
            self.socket.send(b"INICIAR_NEGOCIACION|" + clave_publica_cliente_bytes)
            
            # 3. Recibir CERTIFICADO del servidor (en lugar de solo la clave pública)
            respuesta = self.socket.recv(8192)
            logger.debug(f"Respuesta recibida del servidor...")
            
            if b"CERTIFICADO_SERVIDOR|" in respuesta:
                partes = respuesta.split(b"|", 1)
                certificado_servidor_pem = partes[1]
                
                logger.info("Certificado del servidor recibido. Iniciando verificación...")
                
                # Cargar cadena de confianza (AC1 y AC2)
                cert_ac1, cert_ac2 = cargar_cadena_certificacion()
                
                if cert_ac1 is None or cert_ac2 is None:
                    logger.error("No se pudo cargar la cadena de confianza")
                    print("\n❌ ERROR: No se encontraron los certificados de las ACs")
                    return False
                
                # Verificar el certificado del servidor
                verificado, clave_publica_servidor = verificar_certificado(
                    certificado_servidor_pem, 
                    cert_ac1, 
                    cert_ac2
                )
                
                if not verificado or clave_publica_servidor is None:
                    logger.error("FALLO EN LA VERIFICACIÓN DEL CERTIFICADO")
                    print("\n❌ ALERTA DE SEGURIDAD: El certificado del servidor NO es válido")
                    print("La conexión se ha abortado por seguridad.")
                    return False
                
                # Certificado verificado correctamente
                self.clave_publica_servidor = clave_publica_servidor
                logger.info("✓ Certificado verificado exitosamente")
                print("✓ Certificado del servidor verificado correctamente")
                
                # 4. Generar clave de sesión AES y cifrarla con RSA
                clave_sesion = os.urandom(32)  # 256 bits para AES-256
                logger.info(f"Clave de sesión generada: {len(clave_sesion)} bytes")
                
                clave_sesion_cifrada = encriptar_asimetrico(
                    self.clave_publica_servidor, 
                    base64.b64encode(clave_sesion).decode('utf-8')
                )
                
                if clave_sesion_cifrada:
                    logger.info("Enviando clave de sesión cifrada con RSA...")
                    self.socket.send(f"CLAVE_SESION_CIFRADA|{clave_sesion_cifrada}".encode('utf-8'))
                    
                    # 5. Recibir confirmación
                    confirmacion = self.socket.recv(1024).decode('utf-8')
                    logger.info(f"Confirmación recibida: {confirmacion}")
                    
                    if confirmacion == "NEGOCIACION_EXITOSA":
                        self.establecer_clave_comunicacion(clave_sesion)
                        logger.info("Negociación exitosa - canal seguro establecido (RSA+AES)")
                        return True
                    else:
                        logger.error(f"Confirmación inesperada: {confirmacion}")
                else:
                    logger.error("Error al cifrar clave de sesión con RSA")
            else:
                logger.error("Respuesta del servidor no contiene clave pública")
            
            return False
            
        except Exception as e:
            logger.error(f"Error en negociación de clave: {e}")
            self.desconectar()
            return False
        
    def enviar_comando(self, comando):
        """Envía un comando cifrado con AES-GCM a través del socket"""
        try:
            if not self.socket or not self.conectado:
                logger.error("No hay conexión establecida")
                raise ConnectionError("Sin conexión establecida")
            
            if self.clave_comunicacion:
                logger.debug(f"Cifrando comando: {comando}")
                comando_cifrado = encriptar_mensaje(self.clave_comunicacion, comando)
                
                if not comando_cifrado:
                    logger.error("Error al cifrar comando")
                    raise Exception("Error al cifrar comando")
                
                logger.debug(f"Enviando comando cifrado (longitud: {len(comando_cifrado)})")
                self.socket.send(comando_cifrado.encode('utf-8'))
                
                logger.debug("Esperando respuesta del servidor...")
                respuesta_cifrada = self.socket.recv(4096).decode('utf-8')
                logger.debug(f"Respuesta cifrada recibida (longitud: {len(respuesta_cifrada)})")
                
                if not respuesta_cifrada:
                    logger.error("Servidor cerró la conexión")
                    self.conectado = False
                    raise ConnectionError("El servidor cerró la conexión inesperadamente")
                
                # Verificar mensaje de cierre del servidor
                if respuesta_cifrada == "SERVIDOR_CERRANDO":
                    logger.warning("Servidor notificó que se está cerrando")
                    self.conectado = False
                    raise ConnectionError("El servidor se está cerrando")
                
                respuesta = desencriptar_mensaje(self.clave_comunicacion, respuesta_cifrada)
                
                if not respuesta:
                    logger.error("Error al descifrar respuesta")
                    raise Exception("Error al descifrar respuesta del servidor")
                
                logger.debug(f"Respuesta descifrada: {respuesta}")
                return respuesta
            else:
                logger.error("No hay clave de comunicación establecida")
                raise Exception("No hay clave de comunicación establecida")
                
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as e:
            logger.error(f"Error de conexión: {e}")
            self.conectado = False
            raise ConnectionError(f"Conexión perdida con el servidor: {e}")
        except socket.error as e:
            logger.error(f"Error de socket: {e}")
            self.conectado = False
            raise ConnectionError(f"Error de red: {e}")
        except Exception as e:
            logger.error(f"Error al enviar comando: {e}")
            raise

def obtener_cliente():
    """Obtiene o crea la instancia global del cliente"""
    global _cliente_global
    if _cliente_global is None or not _cliente_global.conectado:
        _cliente_global = ClienteAPI()
        if not _cliente_global.negociar_clave_segura():
            logger.error("No se pudo establecer conexión segura")
            return None
    return _cliente_global

def cerrar_cliente():
    """Cierra la conexión global del cliente"""
    global _cliente_global
    if _cliente_global:
        _cliente_global.desconectar()
        _cliente_global = None

def registrar_usuario(nombre_usuario: str, contraseña: str) -> bool:
    """Registra un usuario mediante comunicación segura"""
    global _cliente_global
    
    api = ClienteAPI()
    
    try:
        if not api.negociar_clave_segura():
            logger.error("Fallo en negociación para registro")
            raise ConnectionError("No se pudo establecer una conexión segura con el servidor")
            
        respuesta = api.enviar_comando(f"REGISTRO|{nombre_usuario}|{contraseña}")
        
        if respuesta == "REGISTRO_EXITOSO":
            _cliente_global = api
            return True
        
        api.desconectar()
        return False
        
    except ConnectionError:
        api.desconectar()
        raise
    except Exception as e:
        logger.error(f"Error en registro: {e}")
        api.desconectar()
        raise ConnectionError(f"Error durante el registro: {e}")

def autenticar_usuario(nombre_usuario: str, contraseña: str) -> bool:
    """Autentica un usuario mediante comunicación segura"""
    global _cliente_global
    
    api = ClienteAPI()
    
    try:
        if not api.negociar_clave_segura():
            logger.error("Fallo en negociación para login")
            raise ConnectionError("No se pudo establecer una conexión segura con el servidor")
            
        respuesta = api.enviar_comando(f"LOGIN|{nombre_usuario}|{contraseña}")
        
        if respuesta == "LOGIN_EXITOSO":
            _cliente_global = api
            logger.info("Login exitoso - conexión persistente establecida con cifrado híbrido")
            return True
        
        api.desconectar()
        return False
        
    except ConnectionError:
        api.desconectar()
        raise
    except Exception as e:
        logger.error(f"Error en login: {e}")
        api.desconectar()
        raise ConnectionError(f"Error durante la autenticación: {e}")

def derivar_clave(contraseña_maestra: str, usuario_autenticado: str) -> bytes | None:
    """Deriva la Clave Maestra de Cifrado (K)"""
    global _cliente_global
    
    api = obtener_cliente()
    if not api:
        logger.error("No hay conexión establecida para derivar clave")
        return None
    
    try:
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
    except Exception as e:
        logger.error(f"Error en derivar_clave: {e}")
        return None

def obtener_citas_usuario(usuario: str) -> tuple[dict, str]:
    """
    Obtiene citas, verifica la firma del servidor y devuelve (citas, firma).
    """
    api = obtener_cliente()
    if not api:
        raise ConnectionError("No se pudo establecer conexión con el servidor")
    
    respuesta = api.enviar_comando(f"OBTENER_CITAS|{usuario}")
    
    if not respuesta or respuesta == "ERROR_FIRMA_SERVIDOR":
        logger.error("Error al recibir citas o firma del servidor.")
        return {}, ""

    try:
        # Esperamos formato: JSON|FIRMA
        if "|" not in respuesta:
            logger.error("Formato de respuesta inválido (falta separador de firma).")
            return {}, ""

        # Separamos por el último pipe
        json_citas_str, firma_b64 = respuesta.rsplit('|', 1)
        
        # VERIFICAR FIRMA usando la clave pública del SERVIDOR
        if verificar_firma(api.clave_publica_servidor, json_citas_str, firma_b64):
            logger.info("Firma del servidor VERIFICADA correctamente. Datos íntegros.")
            return json.loads(json_citas_str), firma_b64
        else:
            logger.critical("FALLO DE SEGURIDAD: La firma del servidor es INVÁLIDA.")
            print("\nALERTA: Los datos recibidos no provienen del servidor legítimo o han sido manipulados.")
            return {}, ""
            
    except Exception as e:
        logger.error(f"Error procesando citas recibidas: {e}")
        return {}, ""

def guardar_cita_servidor(usuario: str, fecha: datetime, motivo_cifrado: str) -> bool:
    """Guarda una cita en el servidor."""

    api = obtener_cliente()
    if not api:
        raise ConnectionError("No se pudo establecer conexión con el servidor")
    
    # Enviamos comando
    fecha_iso = fecha.isoformat()
    comando = f"GUARDAR_CITA|{usuario}|{fecha_iso}|{motivo_cifrado}"

    respuesta = api.enviar_comando(comando)
    return respuesta == "CITA_GUARDADA"

def obtener_cita_servidor(usuario: str, fecha: datetime) -> str:
    """Obtiene una cita específica del servidor"""
    api = obtener_cliente()
    if not api:
        raise ConnectionError("No se pudo establecer conexión con el servidor")
    
    fecha_iso = fecha.isoformat()
    respuesta = api.enviar_comando(f"OBTENER_CITA|{usuario}|{fecha_iso}")
    return respuesta if respuesta != "CITA_NO_ENCONTRADA" else None

def borrar_cita_servidor(usuario: str, fecha: datetime) -> bool:
    """Elimina una cita del servidor"""
    api = obtener_cliente()
    if not api:
        raise ConnectionError("No se pudo establecer conexión con el servidor")
    
    fecha_iso = fecha.isoformat()
    respuesta = api.enviar_comando(f"BORRAR_CITA|{usuario}|{fecha_iso}")
    return respuesta == "CITA_BORRADA"

def aplicacion(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    """Aplicación principal de gestión de citas"""
    while True:
        try:
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
                    eliminar_cita(usuario_autenticado)
                case '5':
                    logger.info("El usuario ha salido de la aplicación.")
                    print("Que tenga un buen dia.")
                    cerrar_cliente()
                    return
                case _:
                    print("Porfavor introduzca un numero del 1 al 5.\n")
        
        except ConnectionError as e:
            logger.error(f"Error de conexión: {e}")
            print(f"\n❌ DESCONEXIÓN INESPERADA")
            print(f"Se ha perdido la conexión con el servidor.")
            print(f"Detalles: {e}")
            print(f"\nLa aplicación se cerrará por seguridad.")
            cerrar_cliente()
            raise
        except KeyboardInterrupt:
            print("\n\nInterrupción del usuario...")
            raise
        except Exception as e:
            logger.error(f"Error inesperado en aplicación: {e}", exc_info=True)
            print(f"\n❌ Error inesperado: {e}")
            print("Por favor, inténtelo de nuevo.")

def ver_citas_pendientes(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    '''Creamos un .txt con la firma y citas pendientes e imprimimos por pantalla las citas.'''
    try:
        # Obtenemos citas y la firma válida
        citas, firma_digital = obtener_citas_usuario(usuario_autenticado)
        
        if not citas:
            logger.info(f"Usuario {usuario_autenticado} sin citas o error de verificación.")
            print("\nNo tiene ninguna cita guardada.")
            return

        # Guardar en fichero de texto
        archivo_salida = f"citas_{usuario_autenticado}.txt"
        try:
            with open(archivo_salida, "w", encoding="utf-8") as f:
                f.write(f"--- REPORTE DE CITAS PARA: {usuario_autenticado} ---\n")
                f.write(f"Fecha de descarga: {datetime.now()}\n")
                f.write("-" * 40 + "\n\n")
                f.write("DATOS (JSON):\n")
                f.write(json.dumps(citas, indent=4))
                f.write("\n\n" + "-" * 40 + "\n")
                f.write("FIRMA DIGITAL DEL SERVIDOR (Verificada):\n")
                f.write(firma_digital)
                f.write("\n" + "-" * 40 + "\n")
            
            logger.info(f"Citas y firma guardadas en {archivo_salida}")
            print(f"\n[INFO] Se ha generado el archivo '{archivo_salida}' con las citas firmadas.")

        except Exception as e:
            logger.error(f"Error escribiendo archivo .txt: {e}")
            print(f"\n[ERROR] No se pudo crear el archivo de respaldo.")

        # Mostrar por pantalla
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
            print("No tiene citas pendientes.")
            return

        citas_pendientes.sort(key=lambda item: item[0])

        for i, (fecha, motivo) in enumerate(citas_pendientes):
            print(f"{i+1}. {fecha.strftime('%d/%m/%Y a las %H:%M')} -> {motivo}")

        print(f"\nTotal: {len(citas_pendientes)} cita(s) pendiente(s).")

    except ConnectionError:
        raise
    except Exception as e:
        logger.error(f"Error al ver citas pendientes: {e}")
        print(f"Error al obtener las citas: {e}")

def crear_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    try:
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
            if guardar_cita_servidor(usuario_autenticado, fecha, motivo_cifrado):
                print("\n¡Cita guardada con éxito!")
            else:
                print("\nError: No se pudo guardar la cita en el servidor.")
        else:
            logger.error(f"Fallo al cifrar la cita para {usuario_autenticado}.")
            print("\nError: No se pudo cifrar la cita.")
    except ConnectionError:
        raise
    except Exception as e:
        logger.error(f"Error al crear cita: {e}")
        print(f"Error al crear la cita: {e}")

def editar_cita(usuario_autenticado:str ,clave_maestra_K:bytes)-> None:
    try:
        fecha_str = input("¿Qué fecha y hora tiene la cita que desea editar? (DD/MM/YYYY hh:mm): ")
        try:
            fecha_antigua = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
        except ValueError:
            logger.warning("Formato de fecha antigua incorrecto.")
            print("Formato de fecha incorrecto.")
            return
        
        motivo_cifrado_antiguo = obtener_cita_servidor(usuario_autenticado, fecha_antigua)
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
        
        if not borrar_cita_servidor(usuario_autenticado, fecha_antigua):
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
        if nuevo_motivo_cifrado and guardar_cita_servidor(usuario_autenticado, fecha_final, nuevo_motivo_cifrado):
            print("\n¡Cita editada con éxito!")
            logger.info(f"Cita editada con éxito para {usuario_autenticado}.")
        else:
            logger.error(f"Fallo al guardar los cambios de la cita para {usuario_autenticado}.")
            print("\nError: Hubo un problema al guardar los cambios de la cita.")
    except ConnectionError:
        raise
    except Exception as e:
        logger.error(f"Error al editar cita: {e}")
        print(f"Error al editar la cita: {e}")

def eliminar_cita(usuario_autenticado:str)-> None:
    try:
        fecha_str = input("¿En qué fecha y hora es la cita que desea eliminar? (DD/MM/YYYY hh:mm): ")
        try:
            fecha_a_eliminar = datetime.strptime(fecha_str, "%d/%m/%Y %H:%M")
        except ValueError:
            logger.warning("Formato de fecha incorrecto para eliminación.")
            print("Formato de fecha incorrecto.")
            return
            
        if borrar_cita_servidor(usuario_autenticado, fecha_a_eliminar):
            print("\n¡Cita eliminada con éxito!")
            logger.info(f"Cita eliminada exitosamente para {usuario_autenticado} en {fecha_a_eliminar.isoformat()}.")
        else:
            print("\nNo se ha encontrado ninguna cita en esa fecha o hubo un error al eliminarla.")
    except ConnectionError:
        raise
    except Exception as e:
        logger.error(f"Error al eliminar cita: {e}")
        print(f"Error al eliminar la cita: {e}")