import base64
import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import re
from datetime import datetime
import random

import tkinter as tk

def main():
    verificador_registros = VerificadorRegistros()
    print("Directorio de trabajo actual:", os.getcwd())
    nombre_usuario = input("Ingrese su nombre de usuario: ")
    contraseña = input("Ingrese su contraseña: ")

    if verificador_registros.authenticate(nombre_usuario, contraseña):
        print("Autenticación exitosa. Bienvenido.")
        cliente_generado = DatosBancarios(verificador_registros)
        numero_cuenta = cliente_generado.generar_numero_cuenta(nombre_usuario)
        cliente_generado.guardar_numero_cuenta(nombre_usuario, numero_cuenta)

        print("Número de cuenta generado:", numero_cuenta)

    else:
        print("Autenticación fallida. Por favor, verifique sus credenciales.")

class VerificadorRegistros:
    def __init__(self):
        # Definimos el archivo donde se almacenarán los datos de usuarios
        self.__database_file = "Registrados.json"
        self.__cuentas_file = "Cuentas.json"


    def load_cuentas(self):
        try:
            with open(self.__cuentas_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def save_cuentas(self, cuentas):
        with open(self.__cuentas_file, "w") as file:
            json.dump(cuentas, file)


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
        "Guardamos los usuarios en el archivo JSON"
        with open(self.__database_file, "w") as file:
            json.dump(usuarios, file)

    def authenticate(self, nombre_usuario: str, contraseña: str):
        usuarios = self.load_users()

        if nombre_usuario in usuarios:
            salt_key = usuarios[nombre_usuario]
            salt_json = bytes.fromhex(salt_key["salt"])
            key_json = salt_key["key"]

            derived_key = self._derive_key(contraseña, salt_json)

            if derived_key == key_json:
                if "dni" not in usuarios[nombre_usuario] or "telefono" not in usuarios[nombre_usuario]:
                    # Si falta DNI o teléfono, solicitarlos y guardarlos
                    dni = input("Ingrese su DNI: ")
                    telefono = input("Ingrese su número de teléfono: ")
                    correo = input("Ingrese su correo electronico: ")
                    calle = input("Ingrese el nombre de su calle: ")
                    edad = input("Ingrese su fecha de nacimiento: ")

                    usuarios[nombre_usuario]["dni"] = dni
                    usuarios[nombre_usuario]["telefono"] = telefono
                    usuarios[nombre_usuario]["correo"] = correo
                    usuarios[nombre_usuario]["calle"] = calle
                    usuarios[nombre_usuario]["edad"] = edad
                    self.save_users(usuarios)

                return True
            else:
                return False
        else:
            print(f"El usuario '{nombre_usuario}' no existe. ¿Desea registrarse?")
            respuesta = input("Sí (s) / No (n): ")
            if respuesta.lower() == "s":
                salt = os.urandom(16)
                key = self._derive_key(contraseña, salt)
                usuarios[nombre_usuario] = {"salt": salt.hex(), "key": key}

                edad = input("Ingrese su fecha de nacimiento: ")
                if self.validar_edad(edad):
                    usuarios[nombre_usuario]["edad"] = edad
                else:
                    print("La edad ingresada no es válido. Debe ser mayor edad para registrarse en nuestra aplicación.")
                    return False

                dni = input("Ingrese su DNI: ")
                if self.validar_dni(dni):
                    usuarios[nombre_usuario]["dni"] = dni
                else:
                    print("El DNI ingresado no es válido.")
                    return False

                telefono = input("Ingrese su número de teléfono: ")
                if self.validar_numero_telefono(telefono):
                    usuarios[nombre_usuario]["telefono"] = telefono
                else:
                    print("El número de teléfono ingresado no es válido.")
                    return False

                correo = input("Ingrese su correo electronico: ")
                if self.validar_correo(correo):
                    usuarios[nombre_usuario]["correo"] = correo


                calle = input("Ingrese el nombre de su calle: ")
                usuarios[nombre_usuario]["calle"] = calle

                self.save_users(usuarios)
                return True
            else:
                return False

    def validar_dni(self, dni):
        tabla_letras = "TRWAGMYFPDXBNJZSQVHLCKE"
        if len(dni) != 9:
            return False
        return True
        #try:
            #num = int(dni[:-1])
        #except ValueError:
            #return False
        #letra = dni[-1]
        #if letra.upper() == tabla_letras[num % 23]:
            #return True
        #return False"""

    def validar_numero_telefono(self, numero):

        patron = re.compile(r'^(\+34|34)?[6-9]\d{8}$')
        return bool(patron.match(numero))

    def validar_edad(self, edad_str):
        try:
            fecha_nacimiento = datetime.strptime(edad_str, '%d/%m/%Y')
            hoy = datetime.now()
            edad = hoy.year - fecha_nacimiento.year - (
                        (hoy.month, hoy.day) < (fecha_nacimiento.month, fecha_nacimiento.day))
            return edad >= 18
        except ValueError:
            return False

    def validar_correo(self, correo):
        patron = r'^[\w\.-]+@[\w\.-]+$'
        return bool(re.match(patron, correo))

class DatosBancarios():

    def __init__(self, verificador_registros):
        self.verificador_registros = verificador_registros

    def obtener_numero_cuenta(self, nombre_usuario):
        cuentas = self.verificador_registros.load_cuentas()
        if nombre_usuario in cuentas:
            return cuentas[nombre_usuario]
        return None
    def guardar_numero_cuenta(self, nombre_usuario, numero_cuenta):
        cuentas = self.verificador_registros.load_cuentas()
        cuentas[nombre_usuario] = numero_cuenta
        self.verificador_registros.save_cuentas(cuentas)

    def generar_numero_cuenta(self, nombre_usuario):
        numero_cuenta_existente = self.obtener_numero_cuenta(nombre_usuario)
        if numero_cuenta_existente:
            return numero_cuenta_existente

        entidad = str(random.randint(1000, 9999))  # Número de entidad ficticio (4 dígitos)
        sucursal = str(random.randint(10, 99))  # Número de sucursal ficticio (2 dígitos)
        dc = str(random.randint(0, 9))  # Dígito de control ficticio (1 dígito)
        cuenta = str(random.randint(1000000000, 9999999999))  # Número de cuenta ficticio (10 dígitos)

        numero_cuenta = entidad + "-" + sucursal + "-" + dc + "-" + cuenta
        return numero_cuenta


if __name__ == "__main__":
    main()
