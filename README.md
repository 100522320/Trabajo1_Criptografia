# Trabajo1_Criptografia

Este es un gestor de citas médicas cifradas que utiliza Python, hashing de contraseñas con Argon2id, derivación de clave con PBKDF2HMAC, y cifrado simétrico AES-GCM para proteger los datos de las citas.

## Cómo Ejecutar el Proyecto (Paso a Paso)

Siga estos pasos para configurar y ejecutar la aplicación correctamente.

### 1. Requisitos Previos
Asegúrese de tener instalado:
* **Python**.
* El gestor de paquetes 'pip'.

### 2. Configuración del Entorno Virtual

Es altamente recomendable crear y activar un entorno virtual para aislar las dependencias del proyecto, ya que el script principal tanto del cliente 
como del servidor ('main.py') intenta cargarlo automáticamente.

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

Inicie dos terminales distintas utilizando los botones "Terminal" -> "New Terminal"

En la primera de las terminales, posiciónese en la carpeta servidor:

'''cd servidor'''

Una vez se encuentre en la carpeta servidor, ejecute el archivo main.py de la siguiente forma:

'''python main.py'''

Antes de iniciarse, el servidor solicitará por terminal que se introduzca la passphrase de su clave privada, 
donde habrá que introducir exactamente la siguiente contraseña:

C0ntr4s3ñ4!

En la segunda de las terminales, posiciónese en la carpeta cliente:

'''cd cliente'''

Una vez se encuentre en la carpeta cliente, ejecute el archivo main.py de la siguiente forma:

'''python main.py'''