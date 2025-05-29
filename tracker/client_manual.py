import socket
import json

def enviar_comando(sock, comando):
    print(f"\nEnviando: {json.dumps(comando, indent=2)}")
    sock.sendall(json.dumps(comando).encode())
    resposta = sock.recv(4096).decode()
    print(f"Recebendo: {json.dumps(json.loads(resposta), indent=2)}")
    return json.loads(resposta)

def main():
    HOST = "localhost"
    PORT = 8000
    
    # Conecta ao servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    print("Cliente conectado ao tracker!")
    print("\nComandos disponíveis:")
    print("1 - REGISTER (registrar novo usuário)")
    print("2 - LOGIN")
    print("3 - REGISTER_FILES (registrar arquivos)")
    print("4 - LIST_PEERS (listar peers)")
    print("5 - LOGOUT")
    print("6 - Sair")
    
    try:
        while True:
            opcao = input("\nDigite o número do comando (1-6): ")
            
            if opcao == "1":
                user = input("Digite o nome de usuário: ")
                password = input("Digite a senha: ")
                enviar_comando(sock, {
                    "cmd": "REGISTER",
                    "user": user,
                    "password": password
                })
                
            elif opcao == "2":
                user = input("Digite o nome de usuário: ")
                password = input("Digite a senha: ")
                enviar_comando(sock, {
                    "cmd": "LOGIN",
                    "user": user,
                    "password": password
                })
                
            elif opcao == "3":
                user = input("Digite seu nome de usuário: ")
                num_files = int(input("Quantos arquivos deseja registrar? "))
                files = []
                
                for i in range(num_files):
                    print(f"\nArquivo {i+1}:")
                    name = input("Nome do arquivo: ")
                    size = int(input("Tamanho em bytes: "))
                    hash_value = input("Hash do arquivo: ")
                    files.append({
                        "name": name,
                        "size": size,
                        "hash": hash_value
                    })
                
                enviar_comando(sock, {
                    "cmd": "REGISTER_FILES",
                    "user": user,
                    "files": files
                })
                
            elif opcao == "4":
                enviar_comando(sock, {
                    "cmd": "LIST_PEERS"
                })
                
            elif opcao == "5":
                user = input("Digite seu nome de usuário: ")
                enviar_comando(sock, {
                    "cmd": "LOGOUT",
                    "user": user
                })
                
            elif opcao == "6":
                print("Encerrando cliente...")
                break
                
            else:
                print("Opção inválida!")
    
    finally:
        sock.close()

if __name__ == "__main__":
    main() 