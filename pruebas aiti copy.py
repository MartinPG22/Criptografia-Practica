import base64
import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import re
from datetime import datetime
import random
import tkinter as tk
import logging
import sys

from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# Configura el nivel de registro
logging.basicConfig(level=logging.DEBUG)

# Configura la salida de registro a la terminal
logging.basicConfig(stream=sys.stdout)


def main(): # Codigo main 
    # Creamos una clase verificador registro para un codigo mas ordenado y coherente
    verificador_registros = VerificadorRegistros()
    # Se pide el usuario y la contraseña para acceder a la aplicación del banco 
    nombre_usuario = input("Ingrese su nombre de usuario: ")
    contraseña = input("Ingrese su contraseña: ")
    
    # Llamamos a la función autenticate para verificar que la contraseña es correcta
    if verificador_registros.authenticate(nombre_usuario, contraseña):
        print("Autenticación exitosa. Bienvenido.")
        # Llamamos a la clase DatosBancarios para trabajar con la cuenta del banco
        cliente_generado = DatosBancarios(verificador_registros)
        # Generamos el numero de cuenta si no existe, y si existe devolvemos el que ya tiene 
        numero_cuenta = cliente_generado.generar_numero_cuenta(nombre_usuario)
        # Una vez obtenido guardamos el numero de cuenta
        cliente_generado.guardar_numero_cuenta(nombre_usuario, numero_cuenta)

        print("Número de cuenta generado:", numero_cuenta)

        
    else:
        print("Autenticación fallida. Por favor, verifique sus credenciales.")
    # Encriptamos la cuenta y generamos un hash para la autenticación de mensaje
    hash = cliente_generado.cfb_encrypt_cuenta(numero_cuenta, nombre_usuario)
    # Desencriptamos la cuenta con ayuda del hash 
    cliente_generado.cfb_decrypt_cuenta(nombre_usuario, hash)

class VerificadorRegistros:
    def __init__(self):
        # Definimos el archivo donde se almacenarán los datos de usuarios
        self.__database_file = "Registrados.json"
        self.__cuentas_file = "Cuentas.json"
        self.__claves_file = "Key.json"

    def load_claves(self):
        # Función para abrir y trabajar con la información del json Key.json
        try:
            with open(self.__claves_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def save_claves(self, keys):
        # Función para guardar las claves en el json key.json
        with open(self.__claves_file, "w") as file:
            json.dump(keys, file)


    def load_cuentas(self):
        # Función para abrir y trabajar con la información del json Cuentas.json
        try:
            with open(self.__cuentas_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def save_cuentas(self, cuentas):
        # Función para guardar las cuentas en el json key.json
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
        # Derivamos la contraseña
        key = kdf.derive(contraseña.encode('utf-8')) 
        return base64.b64encode(key).decode('utf-8')

    def load_users(self):
        # Función para abrir y trabajar con la información del json Registrados.json
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
        # Función para verificar el inicio de sesión del usuario

        # Cargamos los usuarios
        usuarios = self.load_users()
        # Si el usuario ya existe en el json 
        if nombre_usuario in usuarios:
            
            # Cargamos su salt y su contraseña derivada
            salt_key = usuarios[nombre_usuario]
            salt_json = bytes.fromhex(salt_key["salt"])
            key_json = salt_key["key"]

            # Derivamos la contraseña que nos dan en el inicio de sesión 
            derived_key = self._derive_key(contraseña, salt_json)
            
            # Si conincide con la contraseña derivada que teniamos guardada, se da por valido el inicio de sesión 
            if derived_key == key_json:
                return True
            else:
                return False
            
        # Si el usuario no existe preguntaremos si quiere registrarse    
        else:
            print(f"El usuario '{nombre_usuario}' no existe. ¿Desea registrarse?")
            respuesta = input("Sí (s) / No (n): ")
            if respuesta.lower() == "s":

                # Generamos un salt random y derivamos la contraseña
                salt = os.urandom(16)
                key = self._derive_key(contraseña, salt)

                # Guardamos el salt y la contraseña derivada en Registrados.json
                usuarios[nombre_usuario] = {"salt": salt.hex(), "key": key}

                # Información personal que se guarda Registrados.json
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

                # Guardamos los dato en Registrados
                self.save_users(usuarios)
                return True
            else:
                return False

    def validar_dni(self, dni):
        # Función en validar dni
        tabla_letras = "TRWAGMYFPDXBNJZSQVHLCKE"
        if len(dni) != 9:
            return False
        return True

    def validar_numero_telefono(self, numero):
        # Función para validar el numero de telefono
        patron = re.compile(r'^(\+34|34)?[6-9]\d{8}$')
        return bool(patron.match(numero))

    def validar_edad(self, edad_str):
        # Función para validar la edad
        try:
            fecha_nacimiento = datetime.strptime(edad_str, '%d/%m/%Y')
            hoy = datetime.now()
            edad = hoy.year - fecha_nacimiento.year - (
                        (hoy.month, hoy.day) < (fecha_nacimiento.month, fecha_nacimiento.day))
            return edad >= 18
        except ValueError:
            return False

    def validar_correo(self, correo):
        # Función para validar el correo
        patron = r'^[\w\.-]+@[\w\.-]+$'
        return bool(re.match(patron, correo))

class DatosBancarios():
    # Clase para la cuenta bancaria, y lo que vamos a encriptar
    def __init__(self, verificador_registros):
        self.verificador_registros = verificador_registros

    def obtener_numero_cuenta(self, nombre_usuario):
        # Función para obtener los datos de Cuentas.json
        cuentas = self.verificador_registros.load_cuentas()
        if nombre_usuario in cuentas:
            return cuentas[nombre_usuario]
        return None
    
    def guardar_numero_cuenta(self, nombre_usuario, numero_cuenta):
        # Función para guardar en Cuentas.json
        cuentas = self.verificador_registros.load_cuentas()
        cuentas[nombre_usuario] = numero_cuenta
        self.verificador_registros.save_cuentas(cuentas)

    def generar_numero_cuenta(self, nombre_usuario):
        # Se genera un numero de cuenta, si ya existe no lo hace
        numero_cuenta_existente = self.obtener_numero_cuenta(nombre_usuario)
        if numero_cuenta_existente:
            return numero_cuenta_existente

        entidad = str(random.randint(1000, 9999))  # Número de entidad ficticio (4 dígitos)
        sucursal = str(random.randint(10, 99))  # Número de sucursal ficticio (2 dígitos)
        dc = str(random.randint(0, 9))  # Dígito de control ficticio (1 dígito)
        cuenta = str(random.randint(1000000000, 9999999999))  # Número de cuenta ficticio (10 dígitos)

        numero_cuenta = entidad + "-" + sucursal + "-" + dc + "-" + cuenta
        return numero_cuenta


    def cfb_encrypt_cuenta(self, texto_en_claro, usuario):
        print("Encriptar")
        logging.debug("Encriptado con AES en modo CFB")
        keys = self.verificador_registros.load_claves()   # Consigo la clave
        if usuario in keys:
            # Ya se ha encriptado la cuenta
            clave =  keys[usuario]["clave"]

        else:
            # Se genera por primera vez la cuenta y generamos las claves por primera vez  
            clave_bytes = get_random_bytes(16)
            long = len(clave_bytes)
            logging.debug(f"El tamaño de la clave es {long}, se usa el cifrado AES en modo CFB")
            # Para poder guardar la clave en json
            clave = base64.b64encode(clave_bytes).decode('utf-8') 
            # Lo que guardaremos en Key.json
            keys[usuario] = {"clave": clave, "iv": 0, "salt": 0}
            print("clave nueva", clave)
            self.verificador_registros.save_claves(keys)

        print("clave", clave)
        #Encrypt
        # Se convierte en bytes para el uso de los algoritmos
        data = texto_en_claro.encode ('utf-8')
        if len(data) != 20: # La cuenta ya esta encriptado
            print("numero de cuenta ya encriptado")
            ct = self.obtener_numero_cuenta(usuario)
            # Recuperas la cuenta encriptado
            
        if len(data) == 20: # Se acaba de generar la cuenta y todavía no esta encriptada
            print('Texto sin cifrar', data)
            # La clave generada se reconvierte a bytes para usar el AES
            clave = base64.b64decode(clave.encode('utf-8'))
            # Creación de un objeto de cifrado
            cipher_encrypt = AES.new(clave, AES.MODE_CFB)
            # Cifrado de los datos 
            ciphered_bytes = cipher_encrypt.encrypt(data)

            # Guardamos el vector de inicialización para volver a usarlo para desencriptar la información
            iv = b64encode(cipher_encrypt.iv).decode('utf-8')
            keys[usuario]["iv"] = iv 
            self.verificador_registros.save_claves(keys)
            # Mensaje cifrado que guardamos y no esta en bytes
            ct = b64encode(ciphered_bytes).decode('utf-8')

            print('Mensaje cifrado c es: ', ciphered_bytes)
            print('Mensaje cifrado c en base 64: ', ct)

        # Generamos una key para verificar el mensaje cifrado con un hash 
        if usuario in keys:
            salt_hash = keys[usuario]["salt"]
            if salt_hash == 0:          # Usuarios de nueva creación
                salt_hash = os.urandom(16)  # Clave de 16 bytes 
            else:                        # Usamos el salt ya guardado
                salt_hash = bytes.fromhex(salt_hash)

        # Aplicamos el hash sobre la cuenta cifrada 
        ct_hash = self.verificador_registros._derive_key(ct, salt_hash)
        print(ct_hash, "ct_hash")
        # Guardamos el salt para usarlo en el descifrado
        keys[usuario]["salt"] = salt_hash.hex()
        self.verificador_registros.save_claves(keys)
        # Guardamos el numero de cuenta 
        self.guardar_numero_cuenta(usuario, ct)
        # Devolvemos el hash del mensaje cifrado para usarlo en el descifrado 
        return ct_hash         

    def cfb_decrypt_cuenta(self, usuario, hash_x):
        logging.debug("Desencriptado con AES en modo CFB")
        keys = self.verificador_registros.load_claves()   # Consigo la clave
        # Accedemos al salt
        salt_key = keys[usuario]
        salt_json = bytes.fromhex(salt_key["salt"])   

        # Accedemos al vector de inicialización
        iv = keys[usuario]["iv"]
        cuentas = self.verificador_registros.load_cuentas()   
        # Accedemos a la cuenta cifrada
        ct = cuentas[usuario]
        # Derivamos cel mensaje cifrado 
        derived_key = self.verificador_registros._derive_key(ct, salt_json)

        print("Derived_key", derived_key)
        print("hash", hash_x)
        # Comprobamos que el hash recibido es el mismo que el generado con la cuenta cifrada guardada
        if derived_key != hash_x:
            print("El mensaje se ha visto comprometido")
            return False
        
        # Decrypt 
        # El vector de inicialización vuelven a sus bytes originales 
        iv=b64decode(iv.encode('utf-8'))
        # La clave de cifrado vuelven a sus bytes originales 
        key = base64.b64decode(derived_key.encode('utf-8'))
        # Logging del tamaño de clave y metodo de encriptación 
        long = len(key)
        logging.debug(f"El tamaño de la clave es {long}, se usa el cifrado AES en modo CFB")
        # Generamos el objeto de descifrado 
        cipher_decrpyt= AES.new(key, AES.MODE_CFB, iv=iv)
        print("cipher decrypt", cipher_decrpyt)
        
        ctmod = b64decode(ct.encode('utf-8'))
        # Desciframos la cuenta cifrada
        deciphered_bytes = cipher_decrpyt.decrypt(ctmod)
        print("deciphered bytes",deciphered_bytes)
        return deciphered_bytes

if __name__ == "__main__":
    main()