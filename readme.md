# Sistema de Arquivos - A1 de Criptografia

## Tecnologias Utilizadas

- **Java SE 21 (LTS)**
- Sockets TCP

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
