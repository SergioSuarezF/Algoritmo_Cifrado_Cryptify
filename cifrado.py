from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import os
import base64

# Función para generar una clave desde una contraseña
def generar_clave(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

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

# Programa principal
if __name__ == "__main__":
    # Solicitar entrada del usuario
    mensaje = input("Ingresa el mensaje a cifrar: ")
    password = input("Ingresa una contraseña para la clave de cifrado: ")
    
    # Generar salt y clave
    salt = os.urandom(16)
    clave = generar_clave(password, salt)
    
    # Cifrar el mensaje
    mensaje_cifrado, iv = cifrar_aes(mensaje, clave)
    print(f"\nMensaje cifrado: {mensaje_cifrado}")
    print(f"IV (vector de inicialización): {iv}")
    
    # Descifrar el mensaje
    mensaje_descifrado = descifrar_aes(mensaje_cifrado, clave, iv)
    print(f"\nMensaje descifrado: {mensaje_descifrado}")
