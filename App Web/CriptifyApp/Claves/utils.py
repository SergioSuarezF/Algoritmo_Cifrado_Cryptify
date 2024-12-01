# utils.py
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
    clave_invertida = clave[::-1]
    n_caracteres = len(clave)
    clave_modificada = ''.join([f"{n_caracteres}{c}" for c in clave_invertida])
    return clave_modificada

# Función para generar la clave desde la contraseña (modificada)
def generar_clave(password: str, salt: bytes, bits: int) -> bytes:
    password_modificada = modificar_clave(password)
    longitud = {128: 16, 192: 24, 256: 32}[bits]
    kdf_iterations = {128: 10, 192: 12, 256: 14}[bits]
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=longitud,
        salt=salt,
        iterations=kdf_iterations,
        backend=default_backend()
    )
    return kdf.derive(password_modificada.encode())

# Función para cifrar datos con AES
def cifrar_aes(mensaje: str, clave: bytes) -> tuple:
    iv = os.urandom(16)  # Vector de inicialización
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    mensaje_padded = padder.update(mensaje.encode()) + padder.finalize()
    mensaje_cifrado = encryptor.update(mensaje_padded) + encryptor.finalize()
    return base64.b64encode(mensaje_cifrado).decode(), base64.b64encode(iv).decode()

# Función para descifrar datos con AES
def descifrar_aes(mensaje_cifrado: str, clave: bytes, iv: str) -> str:
    mensaje_cifrado_bytes = base64.b64decode(mensaje_cifrado)
    iv_bytes = base64.b64decode(iv)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    mensaje_padded = decryptor.update(mensaje_cifrado_bytes) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    mensaje = unpadder.update(mensaje_padded) + unpadder.finalize()
    return mensaje.decode()

# Función de cifrado César
def cifrado_cesar(mensaje: str, clave: int) -> str:
    resultado = []
    for char in mensaje:
        if char.isalpha():
            desplazamiento = clave % 26
            if char.islower():
                resultado.append(chr((ord(char) - ord('a') + desplazamiento) % 26 + ord('a')))
            elif char.isupper():
                resultado.append(chr((ord(char) - ord('A') + desplazamiento) % 26 + ord('A')))
        else:
            resultado.append(char)
    return ''.join(resultado)

# Función de descifrado César
def descifrado_cesar(mensaje: str, clave: int) -> str:
    return cifrado_cesar(mensaje, -clave)

# Función para calcular la diferencia de fecha y hora
def calcular_diferencia_fecha_hora() -> int:
    fecha_actual = datetime.now()
    fecha = fecha_actual.strftime("%d/%m/%y")
    hora = fecha_actual.strftime("%H:%M:%S")
    suma_fecha = sum(int(x) for x in fecha.split('/'))
    suma_hora = sum(int(x) for x in hora.split(':'))
    diferencia = abs(suma_fecha - suma_hora)
    return diferencia
