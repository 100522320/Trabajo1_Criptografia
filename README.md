# Trabajo1_Criptografia

Este es un gestor de citas médicas cifradas que utiliza Python, hashing de contraseñas con Argon2id, derivación de clave con PBKDF2HMAC, y cifrado simétrico AES-GCM para proteger los datos de las citas.

## Cómo Ejecutar el Proyecto (Paso a Paso)

Siga estos pasos para configurar y ejecutar la aplicación correctamente.

### 1. Requisitos Previos
Asegúrese de tener instalado:
* **Python**.
* El gestor de paquetes 'pip'.

### 2. Configuración del Entorno Virtual

Es altamente recomendable crear y activar un entorno virtual para aislar las dependencias del proyecto, ya que el script principal ('main.py') intenta cargarlo automáticamente.

1.  **Crear el entorno virtual** (nombrado '.venv'):
    '''bash
    python -m venv .venv'''

2.  **Activar el entorno virtual:**
    * **En Linux/macOS:**
        '''bash
        source .venv/bin/activate'''
        
    * **En Windows (Command Prompt):**
        '''bash
        .venv\Scripts\activate'''
        
    * **En Windows (PowerShell):**
        '''powershell
        .venv\Scripts\Activate.ps1'''
        

### 3. Instalación de Dependencias

Instale todos los paquetes necesarios listados en 'requirements.txt':

'''bash
pip install -r requirements.txt'''

### 4. Ejecución del programa

Ejecute el archivo 'main.py' de la siguiente forma:

'''python main.py'''

Tambien puede hacer directamente run de este archivo. 