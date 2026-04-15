# Sistema de Arquivos - A1 de Criptografia

## Tecnologias Utilizadas

- **Java SE 21 (LTS)**
- Sockets TCP

## Métodos Criptográficos utilizados:
- **Criptografia Simétrica:**
    - AES
    - DES
    - ChaCha20 
- **Troca de Chaves**
    - **PKI** (RSA):
        - Chave utilizada na troca de arquivos entre cliente e servidor
    - **Diffie-Hellman** (DH):
        - Chave trocada entre cliente e servidor, mas não utilizada nas transferências
- **Armazenamento de senhas:**
    - SHA-256


## Funcionalidades do Sistema
 - Cadastro de Usuários
 - Login autenticado
 - Upload de Arquivos com transferência criptografada
 - Download de Arquivo com transferência criptografada
 - Listagem de Arquivos no servidor
 - Identificação do Emissor
 - Logs para visualização didática dos procedimentos de comunicação, criptografia, decriptografia e identificação de usuários.

## Como Executar

### Build

```bash
javac -d build server/*.java client/*.java
```

### Execução

Execute em dois terminais separados:

#### Servidor
```
java -cp build server.Server
```

#### Cliente
```
java -cp build client.Client
```

## Usuário padrão

Caso não queira cadastrar um novo usuário:

**Usuário:** admin  
**Senha:** 123

---

## Observações

- Os arquivos enviados são armazenados na pasta: `server/files/`
- A identificação do emissor é mantida no arquivo: `server/files/files.txt`
