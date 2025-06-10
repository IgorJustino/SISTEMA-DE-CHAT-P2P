import socket
import threading
import json
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import time

TRACKER_HOST = 'localhost'
TRACKER_PORT = 8000

# Geração/carregamento de chaves RSA
PRIVATE_KEY_FILE = 'peer_private_key.pem'
PUBLIC_KEY_FILE = 'peer_public_key.pem'

def gerar_ou_carregar_chaves():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        with open(PRIVATE_KEY_FILE, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        with open(PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return private_key, public_key

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def pem_to_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode())

def conectar_tracker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TRACKER_HOST, TRACKER_PORT))
    return sock

def enviar_comando_tracker(sock, comando):
    sock.sendall(json.dumps(comando).encode())
    resposta = sock.recv(4096).decode()
    return json.loads(resposta)

def obter_peers(sock):
    resposta = enviar_comando_tracker(sock, {"cmd": "LIST_PEERS"})
    return resposta.get("peers", {})

# Estrutura para armazenar chaves públicas de outros peers
dict_chaves_peers = {}

# Funções para criptografar e descriptografar mensagens
def criptografar_mensagem(mensagem, public_key):
    return base64.b64encode(
        public_key.encrypt(
            mensagem.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    ).decode()

def descriptografar_mensagem(mensagem_cifrada, private_key):
    return private_key.decrypt(
        base64.b64decode(mensagem_cifrada),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# Função para atuar como servidor de peer
def servidor_peer(private_key, public_key, porta):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("0.0.0.0", porta))
    server_sock.listen()
    print(f"[PEER] Servidor escutando na porta {porta}")
    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_peer_conn, args=(conn, addr, private_key, public_key)).start()

def handle_peer_conn(conn, addr, private_key, public_key):
    try:
        conn.sendall(public_key_to_pem(public_key).encode())
        peer_pub_pem = conn.recv(4096).decode()
        peer_public_key = pem_to_public_key(peer_pub_pem)
        print(f"[PEER] Conectado a {addr}, chave pública recebida.")
        while True:
            data = conn.recv(4096)
            if not data:
                break
            mensagem_cifrada = data.decode()
            mensagem = descriptografar_mensagem(mensagem_cifrada, private_key)
            print(f"[MENSAGEM DE {addr}]: {mensagem}")
            # Salva no histórico se for mensagem de sala
            if mensagem.startswith("[") and "]" in mensagem:
                sala_nome = mensagem[1:mensagem.index("]")]
                if sala_nome not in historico_salas:
                    historico_salas[sala_nome] = []
                historico_salas[sala_nome].append(mensagem)
    except Exception as e:
        print(f"[ERRO] {e}")
    finally:
        conn.close()

# Função para conectar a outro peer e enviar mensagem cifrada
def conectar_e_enviar(ip, porta, minha_public_key, mensagem, peer_public_key):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, porta))
        peer_pub_pem = sock.recv(4096).decode()
        sock.sendall(public_key_to_pem(minha_public_key).encode())
        mensagem_cifrada = criptografar_mensagem(mensagem, peer_public_key)
        sock.sendall(mensagem_cifrada.encode())
    except ConnectionRefusedError:
        print(f"[ERRO] Não foi possível conectar ao peer {ip}:{porta}. Peer offline?")
    finally:
        sock.close()

# Estrutura básica para salas de chat
salas = {}  # sala_nome: [user1, user2, ...]

# Adicionar estrutura para histórico de mensagens
historico_salas = {}

# Função principal
def main():
    private_key, public_key = gerar_ou_carregar_chaves()
    porta_peer = int(input("Digite a porta para escutar conexões de outros peers: "))
    threading.Thread(target=servidor_peer, args=(private_key, public_key, porta_peer), daemon=True).start()
    
    tracker_sock = conectar_tracker()
    print("Conectado ao tracker!")

    # LOGIN/REGISTRO
    while True:
        print("\n1 - Registrar\n2 - Login")
        escolha = input("Escolha uma opção: ")
        user = input("Digite seu nome de usuário: ")
        password = input("Digite sua senha: ")
        if escolha == "1":
            resp = enviar_comando_tracker(tracker_sock, {"cmd": "REGISTER", "user": user, "password": password})
            print(resp.get("msg"))
            # Após registrar, volta ao menu de login/registro
            continue
        elif escolha == "2":
            resp = enviar_comando_tracker(tracker_sock, {"cmd": "LOGIN", "user": user, "password": password, "porta": porta_peer})
            print(resp.get("msg"))
            if resp.get("status") == "OK":
                break
        else:
            print("Opção inválida!")

    # Após login bem-sucedido
    threading.Thread(target=enviar_heartbeat, args=(tracker_sock, user), daemon=True).start()

    while True:
        print("\n1 - Listar peers\n2 - Enviar mensagem cifrada\n3 - Criar sala\n4 - Entrar em sala\n5 - Listar salas\n6 - Enviar mensagem em grupo\n7 - Logout/Sair")
        opcao = input("Escolha uma opção: ")
        if opcao == "1":
            peers = obter_peers(tracker_sock)
            print(json.dumps(peers, indent=2))
        elif opcao == "2":
            peers = obter_peers(tracker_sock)
            if not peers:
                print("Nenhum peer disponível para conversar.")
                continue
            print("Peers disponíveis:")
            peer_list = list(peers.keys())
            for i, peer_user in enumerate(peer_list):
                print(f"{i+1} - {peer_user} ({peers[peer_user]['connection']['ip']}:{peers[peer_user]['connection']['porta']})")
            while True:
                escolha = input("Escolha o peer: ")
                if not escolha.isdigit() or int(escolha) < 1 or int(escolha) > len(peer_list):
                    print("Escolha inválida! Digite o número correspondente ao peer.")
                    continue
                idx = int(escolha) - 1
                break
            peer_user = peer_list[idx]
            ip = peers[peer_user]['connection']['ip']
            porta = peers[peer_user]['connection']['porta']
            mensagem = input("Digite a mensagem: ")
            conectar_e_enviar(ip, porta, public_key, mensagem, public_key)  # Aqui, idealmente, usar a chave pública do peer
        elif opcao == "3":
            nome_sala = input("Nome da sala: ")
            resp = criar_sala(tracker_sock, user, nome_sala)
            print(resp.get("msg"))
            if resp.get("status") == "OK":
                peers = obter_peers(tracker_sock)
                menu_sala(tracker_sock, peers, user, private_key, public_key, nome_sala)
        elif opcao == "4":
            nome_sala = input("Nome da sala para entrar: ")
            resp = entrar_sala(tracker_sock, user, nome_sala)
            print(resp.get("msg"))
            if resp.get("status") == "OK":
                peers = obter_peers(tracker_sock)
                menu_sala(tracker_sock, peers, user, private_key, public_key, nome_sala)
        elif opcao == "5":
            resp = listar_salas(tracker_sock)
            print("Salas disponíveis:", resp.get("rooms", []))
        elif opcao == "6":
            nome_sala = input("Nome da sala: ")
            peers = obter_peers(tracker_sock)
            mensagem = input("Digite a mensagem para o grupo: ")
            enviar_mensagem_grupo(tracker_sock, peers, user, private_key, public_key, nome_sala, mensagem)
        elif opcao == "7":
            # Envia logout ao tracker e encerra
            resp = enviar_comando_tracker(tracker_sock, {"cmd": "LOGOUT", "user": user})
            print(resp.get("msg"))
            print("Saindo...")
            break
        else:
            print("Opção inválida!")

def criar_sala(tracker_sock, user, nome_sala):
    senha = input("Defina uma senha para a sala: ")
    comando = {"cmd": "CREATE_ROOM", "room": nome_sala, "user": user, "senha": senha}
    return enviar_comando_tracker(tracker_sock, comando)

def entrar_sala(tracker_sock, user, nome_sala):
    senha = input("Digite a senha da sala: ")
    comando = {"cmd": "JOIN_ROOM", "room": nome_sala, "user": user, "senha": senha}
    return enviar_comando_tracker(tracker_sock, comando)

def listar_salas(tracker_sock):
    comando = {"cmd": "LIST_ROOMS"}
    return enviar_comando_tracker(tracker_sock, comando)

def obter_membros_sala(tracker_sock, nome_sala):
    resp = enviar_comando_tracker(tracker_sock, {"cmd": "GET_ROOM_MEMBERS", "room": nome_sala})
    if resp.get("status") == "OK":
        return resp.get("members", [])
    return []

def usuario_esta_na_sala(tracker_sock, user, nome_sala):
    membros = obter_membros_sala(tracker_sock, nome_sala)
    return user in membros

def enviar_mensagem_grupo(tracker_sock, peers, user, private_key, public_key, nome_sala, mensagem):
    # Checa se o usuário ainda está na sala
    if not usuario_esta_na_sala(tracker_sock, user, nome_sala):
        print("Você foi expulso da sala!")
        return
    membros = obter_membros_sala(tracker_sock, nome_sala)
    for membro in membros:
        if membro == user:
            continue
        if membro in peers:
            ip = peers[membro]['connection']['ip']
            porta = peers[membro]['connection']['porta']
            conectar_e_enviar(ip, porta, public_key, f"[{nome_sala}] {user}: {mensagem}", public_key)  # Aqui, idealmente, usar a chave pública do peer

def menu_sala(tracker_sock, peers, user, private_key, public_key, nome_sala):
    print(f"\n=== Você está na sala '{nome_sala}' ===")
    while True:
        try:
            membros = obter_membros_sala(tracker_sock, nome_sala)
            admin = membros[0] if membros else None
        except:
            membros = []
            admin = None
        print("\n1 - Enviar mensagem para o grupo")
        print("2 - Listar membros da sala")
        print("3 - Ver histórico de mensagens")
        if user == admin:
            print("4 - Expulsar membro da sala")
            print("5 - Sair da sala")
        else:
            print("4 - Sair da sala")
        opcao = input("Escolha uma opção: ")
        if opcao == "1":
            # Checa se ainda é membro antes de enviar mensagem
            membros = obter_membros_sala(tracker_sock, nome_sala)
            if user not in membros:
                print("Você foi expulso da sala!")
                break
            mensagem = input("Digite a mensagem para o grupo: ")
            enviar_mensagem_grupo(tracker_sock, peers, user, private_key, public_key, nome_sala, mensagem)
        elif opcao == "2":
            print("Membros da sala:", membros)
        elif opcao == "3":
            hist = historico_salas.get(nome_sala, [])
            if not hist:
                print("Nenhuma mensagem recebida nesta sala ainda.")
            else:
                print("\n--- Histórico de mensagens ---")
                for msg in hist:
                    print(msg)
        elif opcao == "4" and user == admin:
            print("Membros da sala:", membros)
            membro = input("Digite o nome do membro para expulsar: ")
            if membro == admin:
                print("Você não pode expulsar a si mesmo (admin).")
            elif membro not in membros:
                print("Usuário não está na sala.")
            else:
                resp = expulsar_membro(tracker_sock, user, nome_sala, membro)
                print(resp.get("msg"))
        elif (opcao == "4" and user != admin) or (opcao == "5" and user == admin):
            print(f"Saindo da sala '{nome_sala}'...")
            break
        else:
            print("Opção inválida!")

def expulsar_membro(tracker_sock, admin, nome_sala, membro):
    comando = {"cmd": "KICK_MEMBER", "room": nome_sala, "admin": admin, "member": membro}
    return enviar_comando_tracker(tracker_sock, comando)

def enviar_heartbeat(tracker_sock, user):
    while True:
        try:
            enviar_comando_tracker(tracker_sock, {"cmd": "HEARTBEAT", "user": user})
        except Exception as e:
            print(f"[HEARTBEAT] Erro ao enviar heartbeat: {e}")
        time.sleep(60)

if __name__ == "__main__":
    main() 