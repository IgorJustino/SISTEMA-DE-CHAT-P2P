# Sistema de Chat P2P em Rede Local

Este repositório contém a implementação do **Tracker** e do **Cliente Peer** para um sistema de chat P2P em rede local. O tracker central é responsável pela autenticação de usuários, registro de peers e de arquivos compartilhados. Os peers se comunicam diretamente entre si para troca de mensagens e transferência de arquivos.

---

## Estrutura de Diretórios

```
P2P_Redes/
├── tracker/
│   ├── tracker.py        # Código do servidor tracker
│   ├── users.json        # Banco de usuários (hash das senhas)
│   ├── peers.json        # Registro de peers conectados e seus arquivos
│   └── test_client.py    # Script de testes (register, login, register_files, list_peers, logout)
└── peer/                 # (Em futuras etapas) Cliente peer para chat e troca de arquivos
```

---

## Pré-requisitos

* Python 3.8+ instalado
* Biblioteca `cryptography` (se usar RSA) ou `PyNaCl` (se usar ECC)

Instale dependências com:

```bash
pip install cryptography
# ou
pip install pynacl
```

---

## 🚀 Como Executar

### 1. Iniciar o Tracker

No terminal, dentro da pasta `tracker/`, execute:

```bash
python3 tracker.py
```

O tracker ficará escutando em `0.0.0.0:8000`.

### 2. Rodar o Script de Testes

Em outro terminal, ainda em `tracker/`, execute:

```bash
python3 test_client.py
```

O script irá realizar, em sequência:

1. **REGISTER**: cria um novo usuário
2. **LOGIN**: faz login desse usuário
3. **REGISTER\_FILES**: registra uma lista de arquivos do peer
4. **LIST\_PEERS**: lista peers ativos e seus arquivos
5. **LOGOUT**: faz logout do peer
6. **LIST\_PEERS**: verifica que a lista ficou vazia após logout

Você verá no terminal as respostas do tracker em formato JSON.

---

## 📋 Comandos Suportados

O tracker entende mensagens JSON via socket TCP na porta 8000. Formato geral:

```json
{ "action": "COMANDO", /* parâmetros */ }
```

| Comando          | Parâmetros                                                    | Descrição                                  |
| ---------------- | ------------------------------------------------------------- | ------------------------------------------ |
| `REGISTER`       | `user`, `password`                                            | Registra um novo usuário                   |
| `LOGIN`          | `user`, `password`                                            | Autentica o usuário                        |
| `REGISTER_FILES` | `user`, `files` (lista de objetos com `name`, `size`, `hash`) | Registra arquivos compartilhados pelo peer |
| `LIST_PEERS`     | *(sem parâmetros)*                                            | Retorna peers ativos e seus arquivos       |
| `LOGOUT`         | `user`                                                        | Desconecta o peer e remove do registro     |

---

## Exemplo de Mensagens

**LOGIN**

```json
{ "action": "LOGIN", "user": "igor", "password": "12345" }
```

**REGISTER\_FILES**

```json
{
  "action": "REGISTER_FILES",
  "user": "igor",
  "files": [
    { "name": "video.mp4", "size": 1024000, "hash": "abc123" },
    { "name": "foto.jpg",  "size":   50000, "hash": "def456" }
  ]
}
```

---

## 📄 peers.json

Exemplo de conteúdo de `peers.json` após registro de arquivos:

```json
{
  "igor": {
    "connection": {
      "ip": "127.0.0.1",
      "porta": 37562,
      "login_time": "2025-05-26T08:41:10.491540"
    },
    "files": [
      { "name": "video.mp4", "size": 1024000, "hash": "abc123" },
      { "name": "foto.jpg",  "size":   50000, "hash": "def456" }
    ]
  }
}
```



