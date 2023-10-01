import json

class UserManager:
    def __init__(self) -> None:
        pass

    def validar_usuario(self, file):
        with open(file, encoding="utf8") as f_u:
            data = json.load(f_u)
        
        validated = False
        for item in data:
            if data["OrderId"] == item['_OrderRequest__order_id']:
                validated = True