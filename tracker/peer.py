import socket
import threading
import json
import os
import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import time
import shutil
from colorama import Fore, Style, init

# Inicializa colorama
init(autoreset=True)

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
        print_colorido(f"[PEER] Conectado a {addr}, chave pública recebida.", Cores.INFO)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            mensagem_cifrada = data.decode()
            mensagem = descriptografar_mensagem(mensagem_cifrada, private_key)
            
            # Colore mensagens baseado no tipo
            if mensagem.startswith("[") and "]" in mensagem:
                # Mensagem de grupo (sala)
                print_colorido(f"[MENSAGEM DE GRUPO {addr}]: {mensagem}", Cores.MENSAGEM_GRUPO)
                sala_nome = mensagem[1:mensagem.index("]")]
                adicionar_mensagem_sala(sala_nome, mensagem)
            else:
                # Mensagem privada
                print_colorido(f"[MENSAGEM PRIVADA {addr}]: {mensagem}", Cores.MENSAGEM_PRIVADA)
    except Exception as e:
        print_colorido(f"[ERRO] {e}", Cores.ERRO)
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
        print_colorido(f"[ERRO] Não foi possível conectar ao peer {ip}:{porta}. Peer offline?", Cores.ERRO)
    finally:
        sock.close()

# Estrutura básica para salas de chat
salas = {}  # sala_nome: [user1, user2, ...]

# Adicionar estrutura para histórico de mensagens
historico_salas = {}

# Arquivo para persistir mensagens das salas
MENSAGENS_FILE = 'mensagens_salas.json'

def carregar_mensagens_salas():
    """Carrega as mensagens das salas do arquivo"""
    try:
        if os.path.exists(MENSAGENS_FILE):
            with open(MENSAGENS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print_colorido(f"[AVISO] Erro ao carregar mensagens: {e}", Cores.DEBUG)
    return {}

def salvar_mensagens_salas():
    """Salva as mensagens das salas no arquivo"""
    try:
        with open(MENSAGENS_FILE, 'w', encoding='utf-8') as f:
            json.dump(historico_salas, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print_colorido(f"[ERRO] Erro ao salvar mensagens: {e}", Cores.ERRO)

def adicionar_mensagem_sala(nome_sala, mensagem):
    """Adiciona uma mensagem ao histórico da sala e salva no arquivo"""
    if nome_sala not in historico_salas:
        historico_salas[nome_sala] = []
    
    # Adiciona timestamp à mensagem
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mensagem_com_timestamp = f"[{timestamp}] {mensagem}"
    
    historico_salas[nome_sala].append(mensagem_com_timestamp)
    
    # Limita o histórico a 100 mensagens por sala para não sobrecarregar
    if len(historico_salas[nome_sala]) > 100:
        historico_salas[nome_sala] = historico_salas[nome_sala][-100:]
    
    salvar_mensagens_salas()
    return mensagem_com_timestamp

def limpar_historico_sala(nome_sala):
    """Remove todas as mensagens de uma sala específica"""
    if nome_sala in historico_salas:
        del historico_salas[nome_sala]
        salvar_mensagens_salas()
        return True
    return False

# Códigos de cores ANSI para terminal
class Cores:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Cores básicas
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Cores de fundo
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    
    # Cores específicas para o chat
    MENSAGEM_PRIVADA = '\033[36m'      # Ciano para mensagens privadas
    MENSAGEM_GRUPO = '\033[33m'        # Amarelo para mensagens de grupo
    MENSAGEM_ENVIADA = '\033[32m'      # Verde para mensagens enviadas
    ERRO = '\033[31m'                  # Vermelho para erros
    INFO = '\033[34m'                  # Azul para informações
    SUCESSO = '\033[32m'               # Verde para sucessos
    DEBUG = '\033[90m'                 # Cinza para debug
    ADMIN = '\033[35m'                 # Magenta para admin

def colorir(texto, cor):
    """Aplica cor ao texto"""
    return f"{cor}{texto}{Cores.RESET}"

def print_colorido(texto, cor):
    """Imprime texto colorido"""
    print(colorir(texto, cor))

def obter_largura_terminal():
    """Obtém a largura do terminal ou usa um valor padrão"""
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80

def exibir_cabecalho_menu(user=""):
    """Exibe o cabeçalho do menu principal no estilo MOONLIGHTER"""
    largura_terminal = obter_largura_terminal()
    
    # Cabeçalho principal
    linha_superior = f"{Fore.LIGHTGREEN_EX}{Style.BRIGHT}╔════════════════════[ SISTEMA CHAT P2P ]════════════════════╗"
    linha_inferior = f"{Fore.LIGHTGREEN_EX}{Style.BRIGHT}╚════════════════════════════════════════════════════════════╝"
    
    # Centraliza a caixa inteira na tela
    largura_caixa = 62  # Largura da caixa ASCII
    espacos_laterais = (largura_terminal - largura_caixa) // 2
    margem = " " * espacos_laterais
    
    print(f"\n{margem}{linha_superior}")
    
    if user:
        # Calcula espaços para centralizar dentro da caixa (60 caracteres internos)
        texto_user = f"USUÁRIO: {user}"
        espacos_user = (60 - len(texto_user)) // 2
        
        texto_status = "STATUS: Online | PEER-TO-PEER CONECTADO"
        espacos_status = (60 - len(texto_status)) // 2
        
        print(f"{margem}{Fore.LIGHTGREEN_EX}║{' ' * espacos_user}{Fore.LIGHTWHITE_EX}{Style.BRIGHT}{texto_user}{' ' * (60 - len(texto_user) - espacos_user)}{Fore.LIGHTGREEN_EX}║")
        print(f"{margem}{Fore.LIGHTGREEN_EX}║{' ' * espacos_status}{Fore.LIGHTCYAN_EX}{Style.BRIGHT}{texto_status}{' ' * (60 - len(texto_status) - espacos_status)}{Fore.LIGHTGREEN_EX}║")
    else:
        texto1 = "SISTEMA DE COMUNICAÇÃO DESCENTRALIZADA"
        texto2 = "MENU PRINCIPAL"
        
        espacos1 = (60 - len(texto1)) // 2
        espacos2 = (60 - len(texto2)) // 2
        
        print(f"{margem}{Fore.LIGHTGREEN_EX}║{' ' * espacos1}{Fore.LIGHTWHITE_EX}{Style.BRIGHT}{texto1}{' ' * (60 - len(texto1) - espacos1)}{Fore.LIGHTGREEN_EX}║")
        print(f"{margem}{Fore.LIGHTGREEN_EX}║{' ' * espacos2}{Fore.LIGHTCYAN_EX}{Style.BRIGHT}{texto2}{' ' * (60 - len(texto2) - espacos2)}{Fore.LIGHTGREEN_EX}║")
    
    print(f"{margem}{linha_inferior}")
    print()

def exibir_cabecalho_sala(nome_sala, user="", admin=""):
    """Exibe o cabeçalho da sala de chat no estilo MOONLIGHTER"""
    largura_terminal = obter_largura_terminal()
    
    # Limita o nome da sala
    nome_limitado = nome_sala[:35] if len(nome_sala) > 35 else nome_sala
    
    # Cabeçalho da sala
    linha_superior = f"{Fore.LIGHTYELLOW_EX}{Style.BRIGHT}╔══════════════════[ SALA DE CHAT ]══════════════════╗"
    linha_inferior = f"{Fore.LIGHTYELLOW_EX}{Style.BRIGHT}╚════════════════════════════════════════════════════╝"
    
    # Centraliza a caixa inteira na tela
    largura_caixa = 54  # Largura da caixa ASCII da sala
    espacos_laterais = (largura_terminal - largura_caixa) // 2
    margem = " " * espacos_laterais
    
    print(f"\n{margem}{linha_superior}")
    
    # Nome da sala
    texto_sala = f"SALA: {nome_limitado}"
    espacos_sala = (52 - len(texto_sala)) // 2
    print(f"{margem}{Fore.LIGHTYELLOW_EX}║{' ' * espacos_sala}{Fore.LIGHTWHITE_EX}{Style.BRIGHT}{texto_sala}{' ' * (52 - len(texto_sala) - espacos_sala)}{Fore.LIGHTYELLOW_EX}║")
    
    # Mostra informações do usuário
    if user:
        if user == admin:
            status_info = f"USUÁRIO: {user} | STATUS: ADMINISTRADOR"
            espacos_status = (52 - len(status_info)) // 2
            print(f"{margem}{Fore.LIGHTYELLOW_EX}║{' ' * espacos_status}{Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}{status_info}{' ' * (52 - len(status_info) - espacos_status)}{Fore.LIGHTYELLOW_EX}║")
        else:
            status_info = f"USUÁRIO: {user} | STATUS: MEMBRO"
            espacos_status = (52 - len(status_info)) // 2
            print(f"{margem}{Fore.LIGHTYELLOW_EX}║{' ' * espacos_status}{Fore.LIGHTCYAN_EX}{Style.BRIGHT}{status_info}{' ' * (52 - len(status_info) - espacos_status)}{Fore.LIGHTYELLOW_EX}║")
    
    print(f"{margem}{linha_inferior}")
    print()

# Função principal
def main():
    # Carrega o histórico de mensagens das salas
    global historico_salas
    historico_salas = carregar_mensagens_salas()
    print_colorido(f"[INFO] Carregadas mensagens de {len(historico_salas)} salas.", Cores.INFO)
    
    private_key, public_key = gerar_ou_carregar_chaves()
    porta_peer = int(input("Digite a porta para escutar conexões de outros peers: "))
    threading.Thread(target=servidor_peer, args=(private_key, public_key, porta_peer), daemon=True).start()
    
    tracker_sock = conectar_tracker()
    print_colorido("Conectado ao tracker!", Cores.SUCESSO)

    # LOGIN/REGISTRO
    while True:
        print_colorido("\n=== SISTEMA DE CHAT P2P ===", Cores.BOLD + Cores.CYAN)
        print_colorido("1 - Registrar", Cores.GREEN)
        print_colorido("2 - Login", Cores.BLUE)
        escolha = input(colorir("Escolha uma opção: ", Cores.WHITE))
        user = input(colorir("Digite seu nome de usuário: ", Cores.WHITE))
        password = input(colorir("Digite sua senha: ", Cores.WHITE))
        if escolha == "1":
            resp = enviar_comando_tracker(tracker_sock, {"cmd": "REGISTER", "user": user, "password": password})
            if resp.get("status") == "OK":
                print_colorido(resp.get("msg"), Cores.SUCESSO)
            else:
                print_colorido(resp.get("msg"), Cores.ERRO)
            # Após registrar, volta ao menu de login/registro
            continue
        elif escolha == "2":
            resp = enviar_comando_tracker(tracker_sock, {"cmd": "LOGIN", "user": user, "password": password, "porta": porta_peer})
            if resp.get("status") == "OK":
                print_colorido(resp.get("msg"), Cores.SUCESSO)
                break
            else:
                print_colorido(resp.get("msg"), Cores.ERRO)
        else:
            print_colorido("Opção inválida!", Cores.ERRO)

    # Após login bem-sucedido
    threading.Thread(target=enviar_heartbeat, args=(tracker_sock, user), daemon=True).start()

    while True:
        # Verifica se o usuário ainda tem salas ativas
        usuario_tem_salas = usuario_tem_salas_ativas(tracker_sock, user)
        
        exibir_cabecalho_menu(user)
        print_colorido("1 - Listar peers", Cores.CYAN)
        print_colorido("2 - Enviar mensagem cifrada", Cores.MENSAGEM_PRIVADA)
        print_colorido("3 - Criar sala", Cores.GREEN)
        print_colorido("4 - Entrar em sala", Cores.BLUE)
        print_colorido("5 - Listar salas", Cores.YELLOW)
        
        # Só mostra opção de enviar mensagem em grupo se o usuário estiver em alguma sala
        if usuario_tem_salas:
            print_colorido("6 - Enviar mensagem em grupo", Cores.MENSAGEM_GRUPO)
            print_colorido("7 - Logout/Sair", Cores.RED)
        else:
            print_colorido("6 - Logout/Sair", Cores.RED)
        
        opcao = input(colorir("Escolha uma opção: ", Cores.WHITE))
        if opcao == "1":
            peers = obter_peers(tracker_sock)
            print(json.dumps(peers, indent=2))
        elif opcao == "2":
            peers = obter_peers(tracker_sock)
            if not peers:
                print_colorido("Nenhum peer disponível para conversar.", Cores.ERRO)
                continue
            print_colorido("Peers disponíveis:", Cores.INFO)
            peer_list = list(peers.keys())
            for i, peer_user in enumerate(peer_list):
                print_colorido(f"{i+1} - {peer_user} ({peers[peer_user]['connection']['ip']}:{peers[peer_user]['connection']['porta']})", Cores.CYAN)
            while True:
                escolha = input(colorir("Escolha o peer: ", Cores.WHITE))
                if not escolha.isdigit() or int(escolha) < 1 or int(escolha) > len(peer_list):
                    print_colorido("Escolha inválida! Digite o número correspondente ao peer.", Cores.ERRO)
                    continue
                idx = int(escolha) - 1
                break
            peer_user = peer_list[idx]
            ip = peers[peer_user]['connection']['ip']
            porta = peers[peer_user]['connection']['porta']
            mensagem = input(colorir("Digite a mensagem: ", Cores.WHITE))
            conectar_e_enviar(ip, porta, public_key, mensagem, public_key)
            print_colorido(f"[MENSAGEM PRIVADA ENVIADA PARA {peer_user}]: {mensagem}", Cores.MENSAGEM_ENVIADA)
        elif opcao == "3":
            nome_sala = input(colorir("Nome da sala: ", Cores.WHITE))
            resp = criar_sala(tracker_sock, user, nome_sala)
            if resp.get("status") == "OK":
                print_colorido(resp.get("msg"), Cores.SUCESSO)
                peers = obter_peers(tracker_sock)
                menu_sala(tracker_sock, peers, user, private_key, public_key, nome_sala)
            else:
                print_colorido(resp.get("msg"), Cores.ERRO)
        elif opcao == "4":
            nome_sala = input(colorir("Nome da sala para entrar: ", Cores.WHITE))
            resp = entrar_sala(tracker_sock, user, nome_sala)
            if resp.get("status") == "OK":
                print_colorido(resp.get("msg"), Cores.SUCESSO)
                peers = obter_peers(tracker_sock)
                menu_sala(tracker_sock, peers, user, private_key, public_key, nome_sala)
            else:
                print_colorido(resp.get("msg"), Cores.ERRO)
        elif opcao == "5":
            resp = listar_salas(tracker_sock)
            salas = resp.get("rooms", [])
            if salas:
                print_colorido("Salas disponíveis:", Cores.INFO)
                for sala in salas:
                    print_colorido(f"  • {sala}", Cores.YELLOW)
            else:
                print_colorido("Nenhuma sala disponível.", Cores.ERRO)
        elif opcao == "6":
            if usuario_tem_salas:
                # Usuário está em alguma sala - pode enviar mensagem em grupo
                nome_sala = input("Nome da sala: ")
                # Verifica se o usuário realmente está nesta sala específica
                if not usuario_esta_na_sala(tracker_sock, user, nome_sala):
                    print(f"Você não está na sala '{nome_sala}' ou foi expulso!")
                    continue
                peers = obter_peers(tracker_sock)
                mensagem = input("Digite a mensagem para o grupo: ")
                enviar_mensagem_grupo(tracker_sock, peers, user, private_key, public_key, nome_sala, mensagem)
            else:
                # Usuário não está em nenhuma sala - logout
                resp = enviar_comando_tracker(tracker_sock, {"cmd": "LOGOUT", "user": user})
                print(resp.get("msg"))
                print("Saindo...")
                break
        elif opcao == "7":
            if usuario_tem_salas:
                # Logout quando usuário tem salas
                resp = enviar_comando_tracker(tracker_sock, {"cmd": "LOGOUT", "user": user})
                print(resp.get("msg"))
                print("Saindo...")
                break
            else:
                print("Opção inválida!")
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

def usuario_tem_salas_ativas(tracker_sock, user):
    """Verifica se o usuário está em alguma sala ativa"""
    try:
        resp_salas = listar_salas(tracker_sock)
        salas_disponiveis = resp_salas.get("rooms", [])
        
        for sala in salas_disponiveis:
            membros = obter_membros_sala(tracker_sock, sala)
            if user in membros:
                return True
        return False
    except:
        return False

def enviar_mensagem_grupo(tracker_sock, peers, user, private_key, public_key, nome_sala, mensagem):
    # Checa se o usuário ainda está na sala
    if not usuario_esta_na_sala(tracker_sock, user, nome_sala):
        print_colorido(centralizar_texto("🚫 VOCÊ FOI EXPULSO DA SALA! 🚫"), Cores.ERRO)
        return
    
    # Adiciona a mensagem ao histórico local com timestamp e salva
    mensagem_formatada = f"[{nome_sala}] {user}: {mensagem}"
    mensagem_com_timestamp = adicionar_mensagem_sala(nome_sala, mensagem_formatada)
    print_colorido(f"[MENSAGEM ENVIADA]: {mensagem_com_timestamp}", Cores.MENSAGEM_ENVIADA)
    
    # Verifica se o usuário é admin para mostrar informações de debug
    membros = obter_membros_sala(tracker_sock, nome_sala)
    admin = membros[0] if membros else None
    
    if user == admin:
        print_colorido(f"[DEBUG - ADMIN] Membros da sala: {membros}", Cores.DEBUG)
        print_colorido(f"[DEBUG - ADMIN] Peers disponíveis: {list(peers.keys())}", Cores.DEBUG)
    
    mensagens_enviadas = 0
    for membro in membros:
        if membro == user:
            continue
        if membro in peers:
            ip = peers[membro]['connection']['ip']
            porta = peers[membro]['connection']['porta']
            if user == admin:
                print_colorido(f"[DEBUG - ADMIN] Enviando mensagem para {membro} ({ip}:{porta})", Cores.DEBUG)
            conectar_e_enviar(ip, porta, public_key, mensagem_formatada, public_key)
            mensagens_enviadas += 1
        else:
            if user == admin:
                print_colorido(f"[DEBUG - ADMIN] Membro {membro} não está na lista de peers conectados", Cores.DEBUG)
    
    if user == admin:
        print_colorido(f"[DEBUG - ADMIN] Total de mensagens enviadas: {mensagens_enviadas}", Cores.DEBUG)

def menu_sala(tracker_sock, peers, user, private_key, public_key, nome_sala):
    while True:
        try:
            # Verifica SEMPRE se o usuário ainda está na sala no início do loop
            membros = obter_membros_sala(tracker_sock, nome_sala)
            if user not in membros:
                mostrar_mensagem_expulsao(nome_sala)
                break
                
            admin = membros[0] if membros else None
        except:
            print_colorido("Erro ao conectar com o servidor. Retornando ao menu principal.", Cores.ERRO)
            break
            
        exibir_cabecalho_sala(nome_sala, user, admin)
        
        print_colorido("1 - Enviar mensagem para o grupo", Cores.MENSAGEM_GRUPO)
        print_colorido("2 - Listar membros da sala", Cores.CYAN)
        print_colorido("3 - Ver histórico de mensagens", Cores.BLUE)
        if user == admin:
            print_colorido("4 - Expulsar membro da sala", Cores.ERRO)
            print_colorido("5 - Limpar histórico da sala", Cores.YELLOW)
            print_colorido("6 - Sair da sala", Cores.RED)
        else:
            print_colorido("4 - Sair da sala", Cores.RED)
        
        opcao = input(colorir("Escolha uma opção: ", Cores.WHITE))
        if opcao == "1":
            # Checa se ainda é membro antes de enviar mensagem
            membros = obter_membros_sala(tracker_sock, nome_sala)
            if user not in membros:
                mostrar_mensagem_expulsao(nome_sala)
                break
            mensagem = input(colorir("Digite a mensagem para o grupo: ", Cores.MENSAGEM_GRUPO))
            # Atualiza peers antes de enviar mensagem
            peers_atualizados = obter_peers(tracker_sock)
            enviar_mensagem_grupo(tracker_sock, peers_atualizados, user, private_key, public_key, nome_sala, mensagem)
        elif opcao == "2":
            # Atualiza a lista de membros antes de mostrar
            membros_atualizados = obter_membros_sala(tracker_sock, nome_sala)
            admin_atualizado = membros_atualizados[0] if membros_atualizados else None
            
            print_colorido(f"Membros da sala '{nome_sala}':", Cores.INFO)
            for i, membro in enumerate(membros_atualizados, 1):
                if membro == admin_atualizado:
                    print_colorido(f"  {i}. {membro} (Administrador)", Cores.ADMIN)
                else:
                    print_colorido(f"  {i}. {membro}", Cores.CYAN)
        elif opcao == "3":
            hist = historico_salas.get(nome_sala, [])
            if not hist:
                print_colorido("Nenhuma mensagem nesta sala ainda.", Cores.INFO)
            else:
                print_colorido(f"\n╔══════════[ HISTÓRICO DA SALA '{nome_sala}' ]══════════╗", Cores.BLUE)
                
                # Mostra as últimas 20 mensagens para não sobrecarregar a tela
                mensagens_recentes = hist[-20:] if len(hist) > 20 else hist
                
                if len(hist) > 20:
                    print_colorido(f"... (mostrando últimas 20 de {len(hist)} mensagens)", Cores.DEBUG)
                
                for msg in mensagens_recentes:
                    # Extrai timestamp e mensagem
                    if msg.startswith("[") and "] " in msg:
                        timestamp_end = msg.find("] ", 1)
                        if timestamp_end != -1:
                            timestamp = msg[1:timestamp_end]
                            mensagem_conteudo = msg[timestamp_end + 2:]
                            print_colorido(f"[{timestamp}]", Cores.DEBUG)
                            print_colorido(f"  {mensagem_conteudo}", Cores.MENSAGEM_GRUPO)
                        else:
                            print_colorido(msg, Cores.MENSAGEM_GRUPO)
                    else:
                        print_colorido(msg, Cores.MENSAGEM_GRUPO)
                
                print_colorido("╚════════════════════════════════════════════════════╝\n", Cores.BLUE)
        elif opcao == "4" and user == admin:
            # Atualiza a lista de membros antes de mostrar
            membros_atualizados = obter_membros_sala(tracker_sock, nome_sala)
            print_colorido("Membros da sala:", Cores.INFO)
            membros_para_expulsar = []
            for i, membro in enumerate(membros_atualizados, 1):
                if membro != admin:  # Não mostra o admin na lista para expulsão
                    print_colorido(f"  {i}. {membro}", Cores.CYAN)
                    membros_para_expulsar.append(membro)
            
            if not membros_para_expulsar:
                print_colorido("Não há outros membros na sala para expulsar.", Cores.INFO)
                continue
            
            membro = input(colorir("Digite o nome do membro para expulsar: ", Cores.WHITE))
            if membro == admin:
                print_colorido("Você não pode expulsar a si mesmo (admin).", Cores.ERRO)
            elif membro not in membros_atualizados:
                print_colorido("Usuário não está na sala.", Cores.ERRO)
            else:
                resp = expulsar_membro(tracker_sock, user, nome_sala, membro)
                print_colorido(resp.get("msg"), Cores.SUCESSO if resp.get("status") == "OK" else Cores.ERRO)
        elif opcao == "5" and user == admin:
            confirmacao = input(colorir("Tem certeza que deseja limpar TODAS as mensagens da sala? (s/n): ", Cores.YELLOW)).lower()
            if confirmacao == 's':
                if limpar_historico_sala(nome_sala):
                    print_colorido(f"Histórico da sala '{nome_sala}' foi limpo com sucesso!", Cores.SUCESSO)
                else:
                    print_colorido("Não havia mensagens para limpar.", Cores.INFO)
            else:
                print_colorido("Operação cancelada.", Cores.INFO)
        elif (opcao == "4" and user != admin) or (opcao == "6" and user == admin):
            print_colorido(f"Saindo da sala '{nome_sala}'...", Cores.INFO)
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

def centralizar_texto(texto, largura=None):
    """Centraliza um texto na linha com base na largura do terminal"""
    if largura is None:
        largura = obter_largura_terminal()
    espacos = (largura - len(texto)) // 2
    return " " * espacos + texto

def mostrar_mensagem_expulsao(nome_sala):
    """Mostra uma mensagem impactante e centralizada de expulsão"""
    os.system('clear' if os.name == 'posix' else 'cls')
    largura = obter_largura_terminal()
    
    # Arte ASCII para "VOCÊ FOI"
    ascii_voce_foi = [
        "██╗   ██╗ ██████╗  ██████╗███████╗    ███████╗ ██████╗ ██╗",
        "██║   ██║██╔═══██╗██╔════╝██╔════╝    ██╔════╝██╔═══██╗██║",
        "██║   ██║██║   ██║██║     █████╗      █████╗  ██║   ██║██║",
        "╚██╗ ██╔╝██║   ██║██║     ██╔══╝      ██╔══╝  ██║   ██║██║",
        " ╚████╔╝ ╚██████╔╝╚██████╗███████╗    ██║     ╚██████╔╝██║",
        "  ╚═══╝   ╚═════╝  ╚═════╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝"
    ]
    
    # Arte ASCII para "EXPULSO"
    ascii_expulso = [
        "███████╗██╗  ██╗██████╗ ██╗   ██╗██╗     ███████╗ ██████╗ ",
        "██╔════╝╚██╗██╔╝██╔══██╗██║   ██║██║     ██╔════╝██╔═══██╗",
        "█████╗   ╚███╔╝ ██████╔╝██║   ██║██║     ███████╗██║   ██║",
        "██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║██║     ╚════██║██║   ██║",
        "███████╗██╔╝ ██╗██║     ╚██████╔╝███████╗███████║╚██████╔╝",
        "╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ "
    ]
    
    # Bordas de emojis (controlando a quantidade para evitar overflow)
    emoji_count = min(largura // 3, 40)  # Máximo 40 emojis
    borda_emoji = "🚫" * emoji_count
    
    print_colorido("\n" + "═" * largura, Cores.ERRO)
    print_colorido(centralizar_texto(borda_emoji), Cores.ERRO)
    print_colorido("", Cores.ERRO)
    
    # Mostra ASCII art centralizada
    for linha in ascii_voce_foi:
        print_colorido(centralizar_texto(linha), Cores.ERRO)
    
    print_colorido("", Cores.ERRO)
    
    for linha in ascii_expulso:
        print_colorido(centralizar_texto(linha), Cores.ERRO)
    
    print_colorido("", Cores.ERRO)
    print_colorido(centralizar_texto(f"🔥 DA SALA '{nome_sala.upper()}' 🔥"), Cores.ERRO)
    print_colorido(centralizar_texto("PELO ADMINISTRADOR!"), Cores.ERRO)
    print_colorido("", Cores.ERRO)
    print_colorido(centralizar_texto(borda_emoji), Cores.ERRO)
    print_colorido("═" * largura, Cores.ERRO)
    print_colorido("", Cores.ERRO)
    print_colorido(centralizar_texto("⏱️  Retornando ao menu principal em 5 segundos..."), Cores.INFO)
    
    time.sleep(5)

if __name__ == "__main__":
    main()