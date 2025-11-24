from datetime import datetime
import threading
import json # Para leer/escribir los datos de la cita cifrada
import logging # AÑADIDO: Importamos el módulo de logging
# Utilidades para conversión
import base64
# Utilidades para la conexión y el protocolo TLS
import socket
import ssl
# Importamos de crypto.py algunas funciones para encriptar y desencriptar las citas
from crypto_servidor import (guardar_cita, obtener_cita, borrar_cita_json, load_citas,
    generar_par_claves, serializar_clave_publica, desencriptar_asimetrico,
    encriptar_mensaje, desencriptar_mensaje,verificar_firma, deserializar_clave_publica)
from auth import registrar_usuario, autenticar_usuario, derivar_clave


# AÑADIDO: Obtener el logger configurado en main.py
logger = logging.getLogger('SecureCitasCLI')


class Servidor:
    def __init__(self):
        self.host = 'localhost'
        self.port = 5000
        self.clientes_conectados = []
        self.clientes_lock = threading.Lock()
        self.servidor_activo = True
        # Generar claves RSA al inicializar
        generar_par_claves()
        logger.info("Servidor inicializado con cifrado híbrido RSA+AES")
    
    def agregar_cliente(self, client_socket):
        """Agrega un cliente a la lista de conectados"""
        with self.clientes_lock:
            self.clientes_conectados.append(client_socket)
            logger.info(f"Cliente agregado. Total conectados: {len(self.clientes_conectados)}")
    
    def remover_cliente(self, client_socket):
        """Remueve un cliente de la lista de conectados"""
        with self.clientes_lock:
            if client_socket in self.clientes_conectados:
                self.clientes_conectados.remove(client_socket)
                logger.info(f"Cliente removido. Total conectados: {len(self.clientes_conectados)}")
    
    def notificar_cierre_servidor(self):
        """Notifica a todos los clientes que el servidor se está cerrando"""
        with self.clientes_lock:
            logger.info(f"Notificando cierre a {len(self.clientes_conectados)} cliente(s)...")
            clientes_notificados = 0
            
            for client_socket in self.clientes_conectados[:]:
                try:
                    mensaje = "SERVIDOR_CERRANDO"
                    client_socket.send(mensaje.encode('utf-8'))
                    clientes_notificados += 1
                    logger.debug(f"Notificación de cierre enviada a cliente")
                except Exception as e:
                    logger.error(f"Error notificando a cliente: {e}")
            
            if clientes_notificados > 0:
                import time
                time.sleep(0.5)
            
            self.clientes_conectados.clear()
            logger.info(f"Se notificó exitosamente a {clientes_notificados} cliente(s)")
        
    def procesar_comando(self, comando, clave_publica_cliente=None):
        """Procesa comandos del cliente"""
        try:
            partes = comando.split('|')
            cmd = partes[0]
            
            if cmd == "INICIAR_NEGOCIACION":
                clave_publica_cliente_bytes = partes[1].encode('utf-8') if len(partes) > 1 else None
                if clave_publica_cliente_bytes:
                    clave_publica_servidor = serializar_clave_publica()
                    return "CLAVE_PUBLICA_SERVIDOR|" + clave_publica_servidor.decode('utf-8')
                return "ERROR_NEGOCIACION"
                
            elif cmd == "CLAVE_SESION_CIFRADA":
                if len(partes) > 1:
                    clave_sesion_cifrada = partes[1]
                    clave_sesion_b64 = desencriptar_asimetrico(clave_sesion_cifrada)
                    if clave_sesion_b64:
                        return "NEGOCIACION_EXITOSA"
                return "ERROR_CLAVE_SESION"
                
            elif cmd == "REGISTRO":
                usuario, password = partes[1], partes[2]
                exito = registrar_usuario(usuario, password)
                return "REGISTRO_EXITOSO" if exito else "REGISTRO_FALLIDO"
                
            elif cmd == "LOGIN":
                usuario, password = partes[1], partes[2]
                exito = autenticar_usuario(usuario, password)
                return "LOGIN_EXITOSO" if exito else "LOGIN_FALLIDO"
                
            elif cmd == "DERIVAR_CLAVE":
                usuario, password = partes[1], partes[2]
                clave_K = derivar_clave(password, usuario)
                if clave_K:
                    return f"CLAVE_CITAS|{base64.b64encode(clave_K).decode('utf-8')}"
                return "ERROR_DERIVACION_CLAVE"
                
            elif cmd == "GUARDAR_CITA":
                if len(partes) != 5: 
                    logger.error("Comando GUARDAR_CITA incompleto (falta firma o datos).")
                    return "ERROR_GUARDAR_CITA"
                
                usuario, fecha_iso, motivo_cifrado, firma_motivo = partes[1], partes[2], partes[3], partes[4]

                # Verificacion de firma
                if not clave_publica_cliente:
                    logger.error("No se encontró la clave pública del cliente para verificar la firma.")
                    return "ERROR_GUARDAR_CITA"
                
                # Ejecutar la verificación de la firma
                if not verificar_firma(clave_publica_cliente, motivo_cifrado, firma_motivo):
                    logger.warning(f"FALLO DE SEGURIDAD: Firma inválida para el usuario {usuario}. Posible manipulación.")
                    return "ERROR_FIRMA_INVALIDA" 
            
                logger.info(f"Firma digital válida para el usuario {usuario}. Procediendo a guardar cita.")

                fecha = datetime.fromisoformat(fecha_iso)
                exito = guardar_cita(usuario, fecha, motivo_cifrado)
                return "CITA_GUARDADA" if exito else "ERROR_GUARDAR_CITA"
                
            elif cmd == "OBTENER_CITAS":
                usuario = partes[1]
                citas = load_citas()
                usuario_citas = citas.get(usuario, {})
                return json.dumps(usuario_citas)
                
            elif cmd == "OBTENER_CITA":
                usuario, fecha_iso = partes[1], partes[2]
                fecha = datetime.fromisoformat(fecha_iso)
                cita = obtener_cita(usuario, fecha)
                return cita if cita else "CITA_NO_ENCONTRADA"
                
            elif cmd == "BORRAR_CITA":
                usuario, fecha_iso = partes[1], partes[2]
                fecha = datetime.fromisoformat(fecha_iso)
                exito = borrar_cita_json(usuario, fecha)
                return "CITA_BORRADA" if exito else "ERROR_BORRAR_CITA"
            
            elif cmd == "DESCONECTAR":
                return "DESCONEXION_OK"
                
            else:
                return "COMANDO_DESCONOCIDO"
                
        except Exception as e:
            logger.error(f"Error procesando comando: {e}")
            return "ERROR_PROCESAMIENTO"

    def manejar_cliente(self, client_socket, addr):
        """Maneja la comunicación con un cliente de forma persistente"""
        clave_sesion = None
        clave_publica_cliente = None
        
        try:
            logger.info(f"Cliente conectado desde {addr}")
            self.agregar_cliente(client_socket)
            
            # FASE 1: Negociación de clave (RSA)
            comando_negociacion = client_socket.recv(4096).decode('utf-8')
            logger.info(f"Fase 1 - Negociación recibida: {comando_negociacion[:100]}...")
            
            if comando_negociacion.startswith("INICIAR_NEGOCIACION|"):
                # Extraer y guardar la clave pública del cliente
                partes_neg = comando_negociacion.split('|', 1)
                if len(partes_neg) > 1:
                 clave_publica_cliente_bytes = partes_neg[1].encode('utf-8')
                 clave_publica_cliente = deserializar_clave_publica(clave_publica_cliente_bytes) 

                respuesta = self.procesar_comando(comando_negociacion)
                client_socket.send(respuesta.encode('utf-8'))
                
                # FASE 2: Recibir clave de sesión cifrada con RSA
                comando_clave = client_socket.recv(4096).decode('utf-8')
                logger.info(f"Fase 2 - Clave sesión recibida: {comando_clave[:100]}...")
                
                if comando_clave.startswith("CLAVE_SESION_CIFRADA|"):
                    respuesta = self.procesar_comando(comando_clave)
                    client_socket.send(respuesta.encode('utf-8'))
                    
                    # Extraer la clave de sesión descifrándola con RSA
                    partes = comando_clave.split('|')
                    clave_sesion_cifrada = partes[1]
                    clave_sesion_b64 = desencriptar_asimetrico(clave_sesion_cifrada)
                    if clave_sesion_b64:
                        clave_sesion = base64.b64decode(clave_sesion_b64)
                        logger.info(f"Clave de sesión establecida: {len(clave_sesion)} bytes")
                    else:
                        logger.error("Error extrayendo clave de sesión")
                        return
                else:
                    logger.error("Formato de clave de sesión incorrecto")
                    return
            else:
                logger.error("No comenzó con negociación")
                return
            
            # FASE 3: Comunicación cifrada con AES-GCM (bucle persistente)
            logger.info("Iniciando comunicación cifrada persistente...")
            
            while self.servidor_activo:
                try:
                    client_socket.settimeout(1.0)
                    
                    try:
                        comando_cifrado = client_socket.recv(4096).decode('utf-8')
                    except socket.timeout:
                        continue
                    
                    client_socket.settimeout(None)
                    
                    if not comando_cifrado:
                        logger.info("Cliente se desconectó (no hay datos)")
                        break
                    
                    logger.debug(f"Comando cifrado recibido: {comando_cifrado[:50]}...")
                    
                    # Descifrar comando con AES-GCM
                    comando = desencriptar_mensaje(clave_sesion, comando_cifrado)
                    if not comando:
                        logger.error("Error descifrando comando")
                        respuesta_cifrada = encriptar_mensaje(clave_sesion, "ERROR_DESCIFRADO")
                        if respuesta_cifrada:
                            client_socket.send(respuesta_cifrada.encode('utf-8'))
                        continue
                    
                    logger.info(f"Comando descifrado: {comando}")
                    
                    if comando == "DESCONECTAR":
                        logger.info("Cliente solicitó desconexión")
                        respuesta_cifrada = encriptar_mensaje(clave_sesion, "DESCONEXION_OK")
                        if respuesta_cifrada:
                            client_socket.send(respuesta_cifrada.encode('utf-8'))
                        break
                    
                    # Procesar comando
                    respuesta = self.procesar_comando(comando, clave_publica_cliente)
                    logger.info(f"Respuesta generada: {respuesta[:100]}...")
                    
                    # Cifrar respuesta con AES-GCM
                    respuesta_cifrada = encriptar_mensaje(clave_sesion, respuesta)
                    if respuesta_cifrada:
                        client_socket.send(respuesta_cifrada.encode('utf-8'))
                        logger.debug("Respuesta enviada cifrada")
                    else:
                        client_socket.send("ERROR_CIFRADO".encode('utf-8'))
                        logger.error("Error cifrando respuesta")
                        
                except socket.error as e:
                    logger.info(f"Error de socket: {e} - Cliente desconectado")
                    break
                except Exception as e:
                    logger.error(f"Error en bucle de comunicación: {e}")
                    break
                        
        except Exception as e:
            logger.error(f"Error con cliente: {e}")
        finally:
            self.remover_cliente(client_socket)
            client_socket.close()
            logger.info(f"Conexión cerrada con {addr}")

    def iniciar(self):
        """Inicia el servidor"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            
            print(f"🖥️  Servidor SecureCitas escuchando en {self.host}:{self.port}")
            print(f"🔐 Cifrado híbrido: RSA-2048 + AES-256-GCM")
            print(f"📋 Presiona Ctrl+C para detener el servidor de forma segura")
            logger.info(f"Servidor iniciado en {self.host}:{self.port} con cifrado híbrido")
            
            while self.servidor_activo:
                try:
                    server_socket.settimeout(1.0)
                    try:
                        client_socket, addr = server_socket.accept()
                    except socket.timeout:
                        continue
                    
                    print(f"🔗 Cliente conectado desde {addr}")
                    
                    threading.Thread(
                        target=self.manejar_cliente, 
                        args=(client_socket, addr), 
                        daemon=True
                    ).start()
                    
                except KeyboardInterrupt:
                    print("\n\n⚠️  Ctrl+C detectado. Cerrando servidor de forma segura...")
                    logger.info("Servidor interrumpido por Ctrl+C")
                    self.servidor_activo = False
                    self.notificar_cierre_servidor()
                    print("✅ Todos los clientes han sido notificados.")
                    break
                    
        except Exception as e:
            logger.error(f"Error en el servidor: {e}")
            print(f"❌ Error en el servidor: {e}")
        finally:
            server_socket.close()
            logger.info("Servidor cerrado")
            print("👋 Servidor cerrado correctamente.")