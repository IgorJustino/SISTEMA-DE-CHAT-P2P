# Sistema de Chat P2P em Rede Local

Este repositório contém a implementação completa de um **Sistema de Chat Peer-to-Peer (P2P)** para rede local com criptografia RSA. O sistema inclui um tracker central para autenticação e descoberta de peers, além de clientes que se comunicam diretamente entre si para troca de mensagens criptografadas e criação de salas de chat.

## 🚀 Funcionalidades

### 🔐 Segurança
- **Criptografia RSA 2048 bits** para todas as comunicações
- **Autenticação segura** com senhas criptografadas
- **Chaves únicas** geradas para cada peer
- **Comunicação P2P criptografada** entre clientes

### 💬 Chat
- **Mensagens individuais** criptografadas entre peers
- **Salas de chat** com múltiplos usuários
- **Administração de salas** (criar, entrar, expulsar membros)
- **Histórico de mensagens** por sala
- **Sistema de heartbeat** para detecção de peers inativos
- **Menu dinâmico** que se adapta ao status do usuário
- **Detecção automática** de expulsão de salas

### 📁 Compartilhamento
- **Registro de arquivos** compartilhados por peer
- **Listagem de peers** e seus arquivos disponíveis

---

## 📋 Pré-requisitos

- Python 3.8+ instalado
- Biblioteca `cryptography` para criptografia RSA

Instale as dependências com:

```bash
pip install cryptography
```

---

## 🚀 Como Executar

### 1. Iniciar o Tracker (Servidor Central)

No terminal, dentro da pasta `tracker/`, execute:

```bash
cd tracker
python3 tracker.py
```

O tracker ficará escutando em `0.0.0.0:8000` e será responsável por:
- Autenticação de usuários
- Registro de peers conectados
- Gerenciamento de salas de chat
- Descoberta de peers para comunicação P2P

### 2. Executar o Cliente Peer

Em outro terminal, ainda na pasta `tracker/`, execute:

```bash
python3 peer.py
```

O cliente solicitará:
1. **Porta para escutar**: Digite uma porta (ex: 9001, 9002, etc.)
2. **Registro/Login**: Escolha se deseja registrar um novo usuário ou fazer login
3. **Credenciais**: Digite usuário e senha

### 3. Menu Principal

Após o login, você terá acesso às seguintes opções:

1. **Listar peers** - Ver usuários conectados
2. **Enviar mensagem cifrada** - Chat individual P2P
3. **Criar sala** - Criar nova sala de chat
4. **Entrar em sala** - Juntar-se a uma sala existente
5. **Listar salas** - Ver salas disponíveis
6. **Enviar mensagem em grupo** - Chat em sala específica (só aparece se estiver em alguma sala)
7. **Logout/Sair** - Desconectar do sistema

> **Nota**: O menu é dinâmico - a opção "Enviar mensagem em grupo" só aparece quando você está participando de alguma sala de chat.

---

## 🔧 Comandos da API do Tracker

O tracker aceita comandos JSON via socket TCP na porta 8000. Formato geral:

```json
{ "cmd": "COMANDO", /* parâmetros específicos */ }
```

### Comandos Disponíveis

| Comando | Parâmetros | Descrição |
|---------|------------|-----------|
| `REGISTER` | `user`, `password` | Registra um novo usuário |
| `LOGIN` | `user`, `password`, `porta` | Autentica usuário e registra peer |
| `REGISTER_FILES` | `user`, `files` | Registra arquivos compartilhados |
| `LIST_PEERS` | *(nenhum)* | Lista peers conectados e arquivos |
| `CREATE_ROOM` | `room`, `user`, `senha` | Cria nova sala de chat |
| `JOIN_ROOM` | `room`, `user`, `senha` | Entra em sala existente |
| `LIST_ROOMS` | *(nenhum)* | Lista salas disponíveis |
| `GET_ROOM_MEMBERS` | `room` | Lista membros de uma sala |
| `KICK_MEMBER` | `room`, `admin`, `member` | Expulsa membro (apenas admin) |
| `HEARTBEAT` | `user` | Mantém conexão ativa |
| `LOGOUT` | `user` | Desconecta peer e limpa registros |

---

## 🏗️ Arquitetura do Sistema

### Componentes Principais

1. **Tracker (`tracker.py`)**
   - Servidor central TCP na porta 8000
   - Gerencia autenticação e registro de peers
   - Mantém estado das salas de chat
   - Remove peers inativos automaticamente (timeout: 5 minutos)

2. **Cliente Peer (`peer.py`)**
   - Interface de usuário para chat
   - Conecta-se ao tracker para descoberta
   - Comunicação P2P direta com outros peers
   - Criptografia/descriptografia de mensagens

### Fluxo de Comunicação

1. **Descoberta**: Peer conecta ao tracker para autenticação
2. **Registro**: Tracker registra IP/porta do peer
3. **Descoberta de Peers**: Cliente consulta tracker para encontrar outros usuários
4. **Comunicação P2P**: Mensagens são enviadas diretamente entre peers
5. **Criptografia**: Todas as mensagens são criptografadas com RSA

---

## 📁 Persistência de Dados

O sistema mantém os seguintes arquivos JSON na pasta `tracker/data/`:

- `users.json` - Usuários registrados e senhas criptografadas
- `peers.json` - Peers atualmente conectados (IP/porta/timestamp)
- `rooms.json` - Salas de chat, membros e administradores
- `files.json` - Arquivos compartilhados por peer

---

## 🔐 Segurança Implementada

- **Criptografia RSA**: Chaves de 2048 bits com padding OAEP
- **Autenticação**: Senhas armazenadas criptografadas no tracker
- **Comunicação P2P**: Mensagens criptografadas ponta-a-ponta
- **Timeout automático**: Peers inativos são removidos após 5 minutos
- **Chaves únicas**: Cada peer gera seu próprio par de chaves RSA

---

## 🎯 Características Técnicas

- **Linguagem**: Python 3.8+
- **Dependências**: `cryptography`
- **Protocolo**: TCP/IP com sockets
- **Criptografia**: RSA-2048 com OAEP padding
- **Arquitetura**: Cliente-Servidor híbrido (tracker) + P2P (peers)
- **Threading**: Suporte a múltiplas conexões simultâneas
- **Timeout**: 5 minutos para desconexão automática

---

## 💡 Exemplo de Uso

### Cenário: Dois usuários conversando

1. **Usuário A** (Porta 9001):
   ```bash
   python3 peer.py
   # Digite a porta: 9001
   # Escolha: 1 (Registrar)
   # Usuário: alice
   # Senha: minhasenha123
   ```

2. **Usuário B** (Porta 9002):
   ```bash
   python3 peer.py
   # Digite a porta: 9002
   # Escolha: 2 (Login)
   # Usuário: bob
   # Senha: senhabob456
   ```

3. **Alice** pode agora:
   - Listar peers para ver "bob" online
   - Enviar mensagem criptografada diretamente para bob
   - Criar uma sala de chat
   - Convidar bob para a sala

### Recursos de Salas de Chat

- **Administrador**: Quem cria a sala torna-se admin
- **Senha da sala**: Necessária para entrar
- **Expulsão**: Apenas admin pode expulsar membros
- **Histórico**: Mensagens recebidas ficam armazenadas localmente
- **Menu adaptativo**: Opções mudam conforme status na sala
- **Detecção de expulsão**: Sistema detecta automaticamente se usuário foi expulso

---

## ⚠️ Notas Importantes

- **Rede Local**: Sistema projetado para funcionar em LAN
- **Firewall**: Certifique-se de que as portas dos peers estão liberadas
- **Backup de Chaves**: As chaves RSA são geradas automaticamente
- **Persistência**: Dados são salvos em arquivos JSON
- **Timeout**: Peers inativos são removidos automaticamente após 5 minutos

---

### Estrutura do Projeto

```
├── tracker/
│   ├── tracker.py              # Servidor tracker principal
│   ├── peer.py                 # Cliente peer (interface do usuário)
│   ├── private_key.pem         # Chave privada do tracker (auto-gerada)
│   ├── public_key.pem          # Chave pública do tracker (auto-gerada)
│   └── data/                   # Dados persistentes (criado automaticamente)
│       ├── users.json          # Usuários registrados
│       ├── peers.json          # Peers conectados
│       ├── rooms.json          # Salas de chat
│       └── files.json          # Arquivos compartilhados
├── peer_private_key.pem        # Chave privada dos peers (auto-gerada)
├── peer_public_key.pem         # Chave pública dos peers (auto-gerada)
└── README.MD                   # Documentação do projeto
```

### 📝 Arquivos por Categoria

**Código fonte principal:**
- `tracker/tracker.py` - Servidor central
- `tracker/peer.py` - Cliente peer

**Dados persistentes:**
- `tracker/data/*.json` - Criados automaticamente conforme uso

**Criptografia:**
- `tracker/*.pem` - Chaves do servidor tracker
- `peer_*.pem` - Chaves dos clientes peer

### 🔧 Melhorias Implementadas

#### Interface Inteligente
- **Menu dinâmico**: Opções mudam conforme o status do usuário
- **Detecção automática**: Sistema identifica se usuário foi expulso de salas
- **Feedback visual**: Mensagens de debug e confirmação

#### Chat em Grupo Otimizado  
- **Admin vê próprias mensagens**: Correção do bug onde admin não via suas mensagens
- **Atualização de peers**: Lista de usuários conectados é atualizada a cada envio
- **Histórico local**: Todas as mensagens ficam salvas localmente

#### Estrutura Limpa
- **Arquivos duplicados removidos**: Projeto otimizado sem redundâncias
- **Organização clara**: Separação lógica entre chaves de tracker e peers
- **Documentação atualizada**: README reflete o estado real do projeto

---

### Próximas Melhorias Possíveis

- [ ] Interface gráfica (GUI)
- [ ] Transferência real de arquivos P2P
- [ ] Notificações de mensagens
- [ ] Histórico persistente de mensagens
- [ ] Criptografia de arquivos compartilhados
- [ ] Suporte a emojis e formatação
- [ ] Chat de voz/vídeo

---

*Desenvolvido como projeto educacional para demonstrar conceitos de redes P2P, criptografia RSA e programação com sockets em Python.*

