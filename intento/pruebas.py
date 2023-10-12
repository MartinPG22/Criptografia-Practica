#pruebas
"""
from intento.UserManager import UserManager
from Crypto.Random import get_random_bytes
key = get_random_bytes(32) # 32 bytes * 8 = 256 bits (1 byte = 8 bits)
print("llave", key)


from Crypto.Random import get_random_bytes
key_location = "D:\\my_key.bin" # A safe place to store a key. Can be on a USB or even locally on the machine (not recommended unless it has been further encrypted)

# Generate the key
key = get_random_bytes(32)
print("llave:", key)
# Save the key to a file
file_out = open(key_location, "wb") # wb = write bytes
file_out.write(key)
file_out.close()

# Later on ... (assume we no longer have the key)
file_in = open(key_location, "rb") # Read bytes
key_from_file = file_in.read() # This key should be the same
file_in.close()

# Since this is a demonstration, we can verify that the keys are the same (just for proof - you don't need to do this)
assert key == key_from_file, 'Keys do not match' # Will throw an AssertionError if they do not match


print("Nombre de usuario", end=" ")
user = input()

user = UserManager("usuarios.json")
"""
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

print("CFB")

key = get_random_bytes(16)
data_to_encrypt = 'Queremos cifrar esto'

#Encrypt
data = data_to_encrypt.encode ('utf-8')
print('Texto sin cifrar', data)

cipher_encrypt = AES.new(key, AES.MODE_CFB)
ciphered_bytes = cipher_encrypt.encrypt(data)

iv = b64encode(cipher_encrypt.iv).decode('utf-8')
ct = b64encode(ciphered_bytes).decode('utf-8')

print('Mensaje cifrado c es: ', ciphered_bytes)


# Decrypt 
iv=b64decode(iv.encode('utf-8'))
cipher_decrpyt= AES.new(key, AES.MODE_CFB, iv=iv)
print(cipher_decrpyt)

ctmod = b64decode(ct.encode('utf-8'))
deciphered_bytes = cipher_decrpyt.decrypt(ctmod)
print(deciphered_bytes)


print("------------------------------------------------------------------")
"""class CFB:
    def __init__(self):
        self.__database_file = "cfb.json"

    def principal(self, data: str):
        archivo = self.load_users

        key = get_random_bytes(32)

        cipher = AES.new(key, AES.MODE_CFB)
        ct_bytes = cipher.encrypt(data)

        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')

        self.save_users(archivo)

        result = json.dumps({'iv':iv, 'ciphertext':ct})
        print(result)

        return True
  
    try:

        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        pt = cipher.decrypt(ct)
        print("The message was: ", pt)

    except (ValueError, KeyError):
        print("Incorrect decryption")

    def load_users(self):
        try:
            # Cargamos los usuarios desde el archivo JSON si existe
            with open(self.__database_file, "r") as file:
                return json.load(file)
        except FileNotFoundError:
            # Si el archivo no existe, devolvemos un diccionario vacío
            return {}
        
    def save_users(self, archivo):
        # Guardamos los usuarios en el archivo JSON
        with open(self.__database_file, "w") as file:
            json.dump(archivo, file)


cifrado = CFB()


mensaje = input("Ingrese su nombre de usuario: ")


if cifrado.principal(mensaje):
    print("Autenticación exitosa. Bienvenido.")
else:
    print("Autenticación fallida. Por favor, verifique sus credenciales.")"""
print("CBC")
# Genera una clave aleatoria de 16 bytes (128 bits)
key = get_random_bytes(16)

data_to_encrypt = 'Europa'

# Encrypt
data = data_to_encrypt.encode('utf-8')
print('Texto sin cifrar:', data)

# Genera un IV (vector de inicialización) aleatorio de 16 bytes
iv = get_random_bytes(16)

# Asegúrate de que el mensaje tenga un tamaño múltiplo del tamaño del bloque (16 bytes en este caso)
while len(data) % 16 != 0:
    data += b' '  # Rellena con espacios en blanco si es necesario

cipher_encrypt = AES.new(key, AES.MODE_CBC, iv)
ciphered_bytes = cipher_encrypt.encrypt(data)

ct = b64encode(ciphered_bytes).decode('utf-8')
iv = b64encode(iv).decode('utf-8')

print('Mensaje cifrado en bytes:', ciphered_bytes)


# Decrypt
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=b64decode(iv.encode('utf-8')))
deciphered_bytes = cipher_decrypt.decrypt(b64decode(ct.encode('utf-8')))

print('Mensaje descifrado en bytes:', deciphered_bytes)
print('Texto descifrado:', deciphered_bytes.rstrip(b' ').decode('utf-8'))

print("------------------------------------------------------------------")