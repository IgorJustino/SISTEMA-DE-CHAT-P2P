import socket
import threading
import json
import hashlib
import datetime
import time

# Tempo máximo de inatividade em segundos (5 minutos)
TIMEOUT_SEGUNDOS = 300

def hash_senha(senha: str) -> str:
    return hashlib.sha256(senha.encode()).hexdigest()

def carregar_usuarios():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def salvar_usuarios(usuarios):
    with open("users.json", "w") as f:
        json.dump(usuarios, f, indent=2)

def carregar_peers():
    try:
        with open("peers.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def salvar_peers(peers):
    with open("peers.json", "w") as f:
        json.dump(peers, f, indent=2)

def carregar_arquivos():
    try:
        with open("files.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def salvar_arquivos(arquivos):
    with open("files.json", "w") as f:
        json.dump(arquivos, f, indent=2)

def handle_client(conn, addr):
    print(f"Nova conexão de {addr}")
    
    while True:
        try:
            # Recebe dados do cliente
            data = conn.recv(4096)
            if not data:
                break
                
            # Decodifica o JSON recebido
            msg = json.loads(data.decode())
            cmd = msg.get("cmd")
            
            # Processa o comando
            if cmd == "REGISTER":
                usuarios = carregar_usuarios()
                user = msg.get("user")
                password = msg.get("password")
                
                if user in usuarios:
                    response = {"status": "ERROR", "msg": "Usuário já existe"}
                else:
                    usuarios[user] = hash_senha(password)
                    salvar_usuarios(usuarios)
                    response = {"status": "OK", "msg": "Usuário registrado com sucesso"}

            elif cmd == "LOGIN":
                usuarios = carregar_usuarios()
                user = msg.get("user")
                password = msg.get("password")
                
                if user in usuarios and usuarios[user] == hash_senha(password):
                    # Login bem sucedido
                    peers = carregar_peers()
                    client_ip, client_port = conn.getpeername()
                    
                    peers[user] = {
                        "ip": client_ip,
                        "porta": client_port,
                        "login_time": datetime.datetime.now().isoformat()
                    }
                    
                    salvar_peers(peers)
                    response = {"status": "OK", "msg": "Login bem-sucedido!"}
                else:
                    response = {"status": "ERROR", "msg": "Credenciais inválidas"}

            elif cmd == "REGISTER_FILES":
                user = msg.get("user")
                files = msg.get("files", [])
                
                if not user:
                    response = {"status": "ERROR", "msg": "Usuário não especificado"}
                else:
                    peers = carregar_peers()
                    if user not in peers:
                        response = {"status": "ERROR", "msg": "Usuário não está logado"}
                    else:
                        arquivos = carregar_arquivos()
                        arquivos[user] = {
                            "files": files,
                            "update_time": datetime.datetime.now().isoformat()
                        }
                        salvar_arquivos(arquivos)
                        response = {"status": "OK", "msg": f"{len(files)} arquivos registrados"}
                    
            elif cmd == "LIST_PEERS":
                peers = carregar_peers()
                arquivos = carregar_arquivos()
                
                # Combina informações de peers com seus arquivos
                peer_info = {}
                for user in peers:
                    peer_info[user] = {
                        "connection": peers[user],
                        "files": arquivos.get(user, {}).get("files", [])
                    }
                
                response = {"status": "OK", "peers": peer_info}
                
            elif cmd == "LOGOUT":
                user = msg.get("user")
                peers = carregar_peers()
                arquivos = carregar_arquivos()
                
                if user in peers:
                    del peers[user]
                    if user in arquivos:
                        del arquivos[user]
                    salvar_peers(peers)
                    salvar_arquivos(arquivos)
                    response = {"status": "OK", "msg": "Logout efetuado com sucesso"}
                else:
                    response = {"status": "ERROR", "msg": "Usuário não está logado"}
                
            else:
                response = {"status": "ERROR", "msg": "Comando inválido"}
            
            # Envia resposta
            conn.sendall(json.dumps(response).encode())
            
        except json.JSONDecodeError:
            print(f"Erro ao decodificar JSON de {addr}")
            break
        except Exception as e:
            print(f"Erro ao processar mensagem de {addr}: {e}")
            break
    
    conn.close()
    print(f"Conexão fechada com {addr}")

def verificar_peers_inativos():
    while True:
        try:
            peers = carregar_peers()
            arquivos = carregar_arquivos()
            tempo_atual = datetime.datetime.now()
            peers_removidos = []

            # Verifica cada peer
            for user in list(peers.keys()):
                ultimo_login = datetime.datetime.fromisoformat(peers[user]['login_time'])
                if (tempo_atual - ultimo_login).total_seconds() > TIMEOUT_SEGUNDOS:
                    print(f"Peer {user} removido por inatividade")
                    del peers[user]
                    if user in arquivos:
                        del arquivos[user]
                    peers_removidos.append(user)

            # Se algum peer foi removido, salva as alterações
            if peers_removidos:
                salvar_peers(peers)
                salvar_arquivos(arquivos)

        except Exception as e:
            print(f"Erro ao verificar peers inativos: {e}")

        # Espera 60 segundos antes da próxima verificação
        time.sleep(60)

def main():
    HOST = "0.0.0.0"
    PORT = 8000
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    
    print(f"Tracker ouvindo em {HOST}:{PORT}")
    
    # Inicia thread de verificação de peers inativos
    thread_timeout = threading.Thread(target=verificar_peers_inativos, daemon=True)
    thread_timeout.start()
    
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

if __name__ == "__main__":
    main() 