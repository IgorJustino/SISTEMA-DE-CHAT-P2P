import socket
import threading
import json
import datetime
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64

# Tempo máximo de inatividade em segundos (5 min)
TIMEOUT_SEGUNDOS = 300

# Gerar par de chaves RSA se não existir
def gerar_chaves_rsa():
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        # Gerar novo par de chaves
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Salvar chaves
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    return private_key, public_key

# Criptografar senha usando RSA
def criptografar_senha(senha: str, public_key) -> str:
    senha_bytes = senha.encode()
    ciphertext = public_key.encrypt(
        senha_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

# Descriptografar senha usando RSA
def descriptografar_senha(senha_criptografada: str, private_key) -> str:
    try:
        ciphertext = base64.b64decode(senha_criptografada)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    except:
        return None

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
    private_key, public_key = gerar_chaves_rsa()
    
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
                
            msg = json.loads(data.decode())
            cmd = msg.get("cmd")
            
            if cmd == "REGISTER":
                usuarios = carregar_usuarios()
                user = msg.get("user")
                password = msg.get("password")
                
                if user in usuarios:
                    response = {"status": "ERROR", "msg": "Usuário já existe"}
                else:
                    # Criptografa a senha antes de salvar
                    senha_criptografada = criptografar_senha(password, public_key)
                    usuarios[user] = senha_criptografada
                    salvar_usuarios(usuarios)
                    response = {"status": "OK", "msg": "Usuário registrado com sucesso"}

            elif cmd == "LOGIN":
                usuarios = carregar_usuarios()
                user = msg.get("user")
                password = msg.get("password")
                
                if user in usuarios:
                    senha_armazenada = usuarios[user]
                    senha_descriptografada = descriptografar_senha(senha_armazenada, private_key)
                    
                    if senha_descriptografada == password:
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
                        response = {"status": "ERROR", "msg": "Senha incorreta"}
                else:
                    response = {"status": "ERROR", "msg": "Usuário não encontrado"}

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