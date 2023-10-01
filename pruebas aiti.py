import base64
import os
import random
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class VerificadorRegistros:
    def __init__(self):
        # Definimos el archivo donde se almacenarán los datos de usuarios
        self.__database_file = "Registrados.json"

    def _derive_key(self, contraseña: str, salt: bytes):
        # Derivamos una clave a partir de la contraseña y el salt usando PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Longitud de la clave derivada
            salt=salt,
            iterations=100000,  # Número de iteraciones
        )
        key = kdf.derive(contraseña.encode('utf-8'))
        return base64.b64encode(key).decode('utf-8')

    def load_users(self):
        try:
            # Cargamos los usuarios desde el archivo JSON si existe
            with open(self.__database_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            # Si el archivo no existe, devolvemos un diccionario vacío
            return {}

    def save_users(self, usuarios):
        # Guardamos los usuarios en el archivo JSON
        with open(self.__database_file, "w") as file:
            json.dump(usuarios, file)

    def authenticate(self, nombre_usuario: str, contraseña: str):
        usuarios = self.load_users()

        if nombre_usuario in usuarios:
            # Si el usuario existe, verificamos la contraseña con el salt almacenado
            salt_key = usuarios[nombre_usuario]
            salt_json = bytes.fromhex(salt_key["salt"])
            key_json = salt_key["key"]

            derived_key = self._derive_key(contraseña, salt_json)

            if derived_key == key_json:
                return True
            else:
                return False
        else:
            # Si el usuario no existe, ofrecemos la opción de registrarse
            print(f"El usuario '{nombre_usuario}' no existe. ¿Desea registrarse?")
            respuesta = input("Sí (s) / No (n): ")
            if respuesta.lower() == "s":
                # Registramos al usuario con un nuevo salt y clave derivada
                salt = os.urandom(16)
                key = self._derive_key(contraseña, salt)
                usuarios[nombre_usuario] = {"salt": salt.hex(), "key": key}
                self.save_users(usuarios)
                return True
            else:
                return False

# Ejemplo de uso
verificador_registros = VerificadorRegistros()

# Usuario proporciona nombre de usuario y contraseña para autenticación
nombre_usuario = input("Ingrese su nombre de usuario: ")
contraseña = input("Ingrese su contraseña: ")

if verificador_registros.authenticate(nombre_usuario, contraseña):
    print("Autenticación exitosa. Bienvenido.")
else:
    print("Autenticación fallida. Por favor, verifique sus credenciales.")
