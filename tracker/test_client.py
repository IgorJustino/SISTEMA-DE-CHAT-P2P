import socket
import json
import sys

def enviar_comando(sock, comando):
    sock.sendall(json.dumps(comando).encode())
    resposta = sock.recv(4096).decode()
    return json.loads(resposta)

def main():
    HOST = "localhost"
    PORT = 8000
    
    # Conecta ao servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    try:
        # Registra um novo usuário
        print("\n=== Teste REGISTER ===")
        resp = enviar_comando(sock, {
            "cmd": "REGISTER",
            "user": "Usuario1",
            "password": "12345"
        })
        print(f"Resposta: {resp}")
        
        # Tenta fazer login com o usuário registrado
        print("\n=== Teste LOGIN ===")
        resp = enviar_comando(sock, {
            "cmd": "LOGIN",
            "user": "Usuario1",
            "password": "12345"
        })
        print(f"Resposta: {resp}")
        
        # Registra alguns arquivos
        print("\n=== Teste REGISTER_FILES ===")
        resp = enviar_comando(sock, {
            "cmd": "REGISTER_FILES",
            "user": "Usuario1",
            "files": [
                {
                    "name": "video.mp4",
                    "size": 1024000,
                    "hash": "abc123"
                },
                {
                    "name": "foto.jpg",
                    "size": 50000,
                    "hash": "def456"
                }
            ]
        })
        print(f"Resposta: {resp}")
        
        # Lista peers (deve mostrar o igor e seus arquivos)
        print("\n=== Teste LIST_PEERS ===")
        resp = enviar_comando(sock, {
            "cmd": "LIST_PEERS"
        })
        print(f"Resposta: {resp}")
        
        # Faz logout
        print("\n=== Teste LOGOUT ===")
        resp = enviar_comando(sock, {
            "cmd": "LOGOUT",
            "user": "Usuario1"
        })
        print(f"Resposta: {resp}")
        
        # Lista peers novamente (deve estar vazio)
        print("\n=== Teste LIST_PEERS (após logout) ===")
        resp = enviar_comando(sock, {
            "cmd": "LIST_PEERS"
        })
        print(f"Resposta: {resp}")
        
    finally:
        sock.close()

if __name__ == "__main__":
    main() 