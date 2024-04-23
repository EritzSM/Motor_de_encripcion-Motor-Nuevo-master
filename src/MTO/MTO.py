from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidKey
import base64
import binascii

class EncryptionError(Exception):

    def NumberOrSpecialcharacter(password):
        if not any(char.isdigit() or not char.isalpha() for char in password):
            raise EncryptionError("La clave debe contener al menos un número o un carácter especial")

    def NotAlphanumerics(password):
        if not password.isalnum():
            raise EncryptionError("La clave contiene caracteres no alfanuméricos")

    def NotSpaces(password):
        if ' ' in password:  # Verifica si hay espacios en la contraseña
            raise EncryptionError("La clave no puede contener espacios")

    def MinimumCharacters(password):
        if len(password) < 4:
            raise EncryptionError("La clave debe tener al menos 4 caracteres")

    def EmptyPassword(password):
        if not password:
            raise EncryptionError("EL campo de contraseña está vacio, por favor rellenelo")

    def EmptyMessage(message):
        if not message:
            raise EncryptionError("El mensaje está vacío, por favor rellene el campo")


class DecryptionError(Exception):

    def NotSpaces(password):
        if ' ' in password:  # Verifica si hay espacios en la contraseña
            raise DecryptionError("La clave no puede contener espacios")

    def EmptyMessage(ciphertext):
        if not ciphertext:
            raise DecryptionError("El mensaje vacio, por favor rellene el campo")

    def MinimumCharacters(password):
        if len(password) < 4:
            raise DecryptionError("La clave debe tener al menos 4 caracteres")

    def EmptyPassword(password):
        if not password:
            raise DecryptionError("La clave está vacía, por favor rellene el campo")


def encrypt_message(message, password):

    try:

        # Verifica que el mensaje no este vacio
        EncryptionError.EmptyMessage(message)
        # Verifica que la clave no este vacia
        EncryptionError.EmptyPassword(password)
        # Verifica que la longitud de la clave sea al menos 4 caracteres
        EncryptionError.MinimumCharacters(password)
        # Verifica que la clave no contenga espacios
        EncryptionError.NotSpaces(password)
        # Verifica que la clave tenga al menos un numero o caracteres alfanumericos
        EncryptionError.NotAlphanumerics(password)
        # Verificar que la clave contenga al menos un número o un carácter especial
        EncryptionError.NumberOrSpecialcharacter(password)

        # Definir una sal (salt) y un factor de iteración
        salt = b'salt_'
        iterations = 100_000
        # Derivar una clave a partir de la contraseña
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Agregar padding al mensaje
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()

        # Inicializar el cifrador
        cipher = Cipher(algorithms.AES(key), modes.CBC(b'0' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encriptar el mensaje
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Devolver el texto cifrado como base64
        return base64.b64encode(ciphertext).decode()
    except Exception as e:
        raise EncryptionError(str(e))



def decrypt_message(ciphertext, password):

    try:

        # Verifica que la clave no este vacia
        DecryptionError.EmptyPassword(password)
        # Verifica que la longitud de la clave sea al menos 4 caracteres
        DecryptionError.MinimumCharacters(password)
        # Verifica que el mensaje no este vacio
        DecryptionError.EmptyMessage(ciphertext)
        # Verifica que la clave no contenga espacios
        DecryptionError.NotSpaces(password)
        # Verificar que la clave contenga al menos un número o un carácter especial
        # Verificar que el mensaje tenga caracteres especiales
        ciphertext = base64.b64decode(ciphertext.encode())
        
        # Derivar la clave de la contraseña
        salt = b'salt_'
        iterations = 100_000
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Inicializar el descifrador
        cipher = Cipher(algorithms.AES(key), modes.CBC(b'0' * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Desencriptar el mensaje y quitar el padding
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        # Verificar que la clave contenga al menos un número o un carácter especial
        # Devolver el mensaje descifrado
        
        return unpadded_data.decode()
    
    except (TypeError, binascii.Error):
            raise DecryptionError("El mensaje cifrado está corrupto o la contraseña es incorrecta")








