import json

class Usuarios:
    def __init__(self, id,  contrasena, token) -> None:
        self.__id = id
        self.__contrasena = contrasena
        self.__token = token

    @property
    def id(self):
        "Property de la variable id"
        return self.__id
    @id.setter
    def id(self, value):
        self.__id = value

    @property
    def contrasena( self ):
        "Property de la variable contraseña"
        return self.__contrasena
    @contrasena.setter
    def contrasena( self, value ):
        self.__contrasena = value

    @property
    def token( self ):
        "Property de la variable token"
        return self.__token
    @token.setter
    def token( self, value ):
        self.__token = value