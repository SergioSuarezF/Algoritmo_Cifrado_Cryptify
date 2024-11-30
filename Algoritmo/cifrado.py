from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import os
import base64
from datetime import datetime

# Función para determinar la longitud de clave basada en la longitud de la contraseña
def determinar_longitud_clave(password: str) -> int:
    if len(password) < 16:
        return 128  # Clave de 128 bits (16 bytes)
    elif len(password) < 24:
        return 192  # Clave de 192 bits (24 bytes)
    else:
        return 256  # Clave de 256 bits (32 bytes)

# Función para invertir la clave y separarla con el número de caracteres
def modificar_clave(clave: str) -> str:
    # Invertir la clave
    clave_invertida = clave[::-1]
    
    # Obtener el número de caracteres de la clave
    n_caracteres = len(clave)
    
    # Crear la nueva clave separada con el número de caracteres
    clave_modificada = ''.join([f"{n_caracteres}{c}" for c in clave_invertida])
    
    return clave_modificada

# Función para generar la clave desde la contraseña (modificada)
def generar_clave(password: str, salt: bytes, bits: int) -> bytes:
    # Modificar la clave antes de generar la clave de cifrado
    password_modificada = modificar_clave(password)
    
    longitud = {128: 16, 192: 24, 256: 32}[bits]
    kdf_iterations = {128: 10, 192: 12, 256: 14}[bits]  # Simulación de rondas
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=longitud,
        salt=salt,
        iterations=kdf_iterations,  # Ajusta las iteraciones según las rondas deseadas
        backend=default_backend()
    )
    return kdf.derive(password_modificada.encode())

# Función para cifrar datos
def cifrar_aes(mensaje: str, clave: bytes) -> tuple:
    iv = os.urandom(16)  # Vector de inicialización
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Añadir padding al mensaje
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    mensaje_padded = padder.update(mensaje.encode()) + padder.finalize()
    
    # Cifrar
    mensaje_cifrado = encryptor.update(mensaje_padded) + encryptor.finalize()
    return base64.b64encode(mensaje_cifrado).decode(), base64.b64encode(iv).decode()

# Función para descifrar datos
def descifrar_aes(mensaje_cifrado: str, clave: bytes, iv: str) -> str:
    mensaje_cifrado_bytes = base64.b64decode(mensaje_cifrado)
    iv_bytes = base64.b64decode(iv)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Descifrar
    mensaje_padded = decryptor.update(mensaje_cifrado_bytes) + decryptor.finalize()
    
    # Quitar padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    mensaje = unpadder.update(mensaje_padded) + unpadder.finalize()
    return mensaje.decode()

# Función para calcular la diferencia entre la fecha y la hora
def calcular_diferencia_fecha_hora():
    # Obtener la fecha y hora actual
    now = datetime.now()
    fecha = now.strftime("%d/%m/%y")  # Formato dd/mm/yy
    hora = now.strftime("%H:%M:%S")  # Formato hh:mm:ss

    # Sumar los valores de la fecha
    fecha_dia, fecha_mes, fecha_anno = map(int, fecha.split('/'))
    suma_fecha = fecha_dia + fecha_mes + fecha_anno

    # Sumar los valores de la hora
    hora_hora, hora_minuto, hora_segundo = map(int, hora.split(':'))
    suma_hora = hora_hora + hora_minuto + hora_segundo

    # Calcular la diferencia
    diferencia = suma_fecha - suma_hora

    # Retornar el valor absoluto de la diferencia
    return abs(diferencia)

# Función de cifrado César
def cifrado_cesar(mensaje: str, clave: int) -> str:
    resultado = []
    for char in mensaje:
        if char.isalpha():
            # Determinar si es mayúscula o minúscula
            start = ord('A') if char.isupper() else ord('a')
            # Aplicar el desplazamiento con la clave
            resultado.append(chr((ord(char) - start + clave) % 26 + start))
        else:
            # Si no es una letra, lo dejamos igual
            resultado.append(char)
    return ''.join(resultado)

# Programa principal
if __name__ == "__main__":
    # Paso 1: Calcular la diferencia fecha-hora
    diferencia = calcular_diferencia_fecha_hora()
    print(f"\nValor absoluto de la diferencia de fecha y hora: {diferencia}")

    # Paso 2: Solicitar entrada del usuario
    mensaje = input("\nIngresa el mensaje a cifrar: ")
    password = input("Ingresa una contraseña para la clave de cifrado: ")
    
    # Determinar tamaño de clave basado en la longitud de la contraseña
    bits = determinar_longitud_clave(password)
    print(f"\nTamaño de clave AES seleccionado automáticamente: {bits} bits")
    
    # Generar salt y clave
    salt = os.urandom(16)
    clave = generar_clave(password, salt, bits)
    
    # Mostrar la clave modificada (invertida y separada)
    print(f"\nClave invertida y separada: {modificar_clave(password)}")
    
    # Cifrar el mensaje
    mensaje_cifrado, iv = cifrar_aes(mensaje, clave)
    print(f"\nMensaje cifrado: {mensaje_cifrado}")
    print(f"IV (vector de inicialización): {iv}")
    
    # Paso 3: Aplicar el cifrado César con la diferencia como clave
    mensaje_cifrado_final = cifrado_cesar(mensaje_cifrado, diferencia)
    print(f"\nMensaje cifrado FINAL con César: {mensaje_cifrado_final}")
    
    # Descifrar el mensaje
    mensaje_descifrado = descifrar_aes(mensaje_cifrado, clave, iv)
    print(f"\nMensaje descifrado: {mensaje_descifrado}")