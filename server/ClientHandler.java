package server;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;


public class ClientHandler extends Thread {

    private Socket socket;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public void run() {
        try {

            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

            String command = dis.readUTF();

            String currentUser = null;
            PublicKey clientPublicKey = null;

            if (command.equals("REGISTER")) {
                String user = dis.readUTF();
                String pass = dis.readUTF();

                boolean ok = UserService.register(user, pass);
                dos.writeUTF(ok ? "REGISTER_OK" : "USER_EXISTS");
                return;
            }

            if (command.equals("LOGIN")) {

                String user = dis.readUTF();
                String pass = dis.readUTF();

                if (!UserService.login(user, pass)) {
                    dos.writeUTF("LOGIN_FAIL");
                    return;
                }

                dos.writeUTF("LOGIN_OK");
                dos.flush();

                currentUser = user;

                KeyExchange.sendPublicKey(dos, Server.keyPair.getPublic());
                clientPublicKey = KeyExchange.receivePublicKey(dis);

                KeyPair dhKeyPair = KeyExchange.generateDH();
                PublicKey clientDhKey = KeyExchange.receiveDHPublicKey(dis);
                KeyExchange.sendDHPublicKey(dos, dhKeyPair.getPublic());
                byte[] sharedSecret = KeyExchange.generateSharedSecret(dhKeyPair.getPrivate(), clientDhKey);

                Logger.logBytes("Chave Privada Diffie-Hellman do Server ", sharedSecret);
            }

            while (true) {

                String cmd = dis.readUTF();

                if (cmd.equals("UPLOAD")) {

                    int alg = dis.readInt();

                    byte[] nonce = null;
                    if (alg == 3) {
                        int nonceSize = dis.readInt();
                        nonce = new byte[nonceSize];
                        dis.readFully(nonce);
                    }

                    String fileName = dis.readUTF();
                    Logger.log("Recebendo arquivo " + fileName + " do usuário " + currentUser);
                    
                    int keySize = dis.readInt();
                    byte[] encryptedKey = new byte[keySize];
                    dis.readFully(encryptedKey);

                    // 🔐 recuperar bytes da chave
                    byte[] keyBytes = KeyExchange.decryptRSA(
                        encryptedKey,
                        Server.keyPair.getPrivate()
                    );

                    int size = dis.readInt();
                    byte[] encryptedData = new byte[size];
                    dis.readFully(encryptedData);

                    Logger.logBytes("Dados criptografados", encryptedData);

                    byte[] data;

                    switch (alg) {

                        case 1:
                            Logger.log("Algoritmo recebido: AES");

                            SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
                            data = CryptoUtils.decryptAES(encryptedData, aesKey);
                            break;

                        case 2:
                            Logger.log("Algoritmo recebido: DES");

                            SecretKey desKey = new SecretKeySpec(keyBytes, "DES");
                            data = CryptoUtils.decryptDES(encryptedData, desKey);
                            break;

                        case 3:
                            Logger.log("Algoritmo recebido: ChaCha20");

                            SecretKey chaKey = new SecretKeySpec(keyBytes, "ChaCha20");
                            data = CryptoUtils.decryptChaCha(encryptedData, chaKey, nonce);
                            break;

                        default:
                            throw new IllegalArgumentException("Algoritmo inválido");
                    }

                    Logger.logBytes("Dados descriptografados", data);

                    Files.write(Paths.get("server/files/" + fileName), data);

                    Path meta = Paths.get("server/files/register/files.txt");
                    Files.createDirectories(meta.getParent());

                    Files.write(meta,
                            (fileName + ";" + currentUser + "\n").getBytes(),
                            StandardOpenOption.CREATE,
                            StandardOpenOption.APPEND);

                    dos.writeUTF("UPLOAD_OK");
                }

                if (cmd.equals("DOWNLOAD")) {

                    String fileName = dis.readUTF();
                    int alg = dis.readInt();

                    Logger.log("Recebendo pedido de download do arquivo " + fileName);
                    Logger.log("Com chave Pública: " + clientPublicKey);

                    byte[] data = Files.readAllBytes(Paths.get("server/files/" + fileName));
                    Logger.logBytes("Dados Originais", data);

                    CryptoInfo cryptoInfo = CriptografaArquivos(alg, data, dos);
                    Logger.logBytes("Dados criptografados", cryptoInfo.encryptedData);

                    byte[] encryptedKey = KeyExchange.encryptRSA(cryptoInfo.key.getEncoded(), clientPublicKey);

                    dos.writeInt(encryptedKey.length);
                    dos.write(encryptedKey);

                    dos.writeInt(cryptoInfo.encryptedData.length);
                    dos.write(cryptoInfo.encryptedData);
                    Logger.log("Arquivo enviado ao cliente");
                }

                if (cmd.equals("LIST")) {
                    
                    Logger.log("Recebendo pedido de listagem de arquivos");
                    Path meta = Paths.get("server/files/register/files.txt");

                    if (!Files.exists(meta)) {
                        dos.writeUTF("END");
                        continue;
                    }

                    List<String> lines = Files.readAllLines(meta);

                    for (String line : lines) {
                        dos.writeUTF(line);
                    }

                    dos.writeUTF("END");
                    Logger.log("Lista de arquivos enviada ao cliente");                        
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private CryptoInfo CriptografaArquivos(int alg, byte[] data, DataOutputStream dos) throws Exception {
        SecretKey key;
        byte[] encryptedData;
        byte[] nonce = null;

        switch (alg) {

            case 1:
                Logger.log("Algoritmo escolhido: AES");
                key = CryptoUtils.generateAESKey();
                encryptedData = CryptoUtils.encryptAES(data, key);
                break;

            case 2:
                Logger.log("Algoritmo escolhido: DES");
                key = CryptoUtils.generateDESKey();
                encryptedData = CryptoUtils.encryptDES(data, key);
                break;

            case 3:
                Logger.log("Algoritmo escolhido: ChaCha20");
                key = CryptoUtils.generateChaChaKey();

                nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);
                encryptedData = CryptoUtils.encryptChaCha(data, key, nonce);
                
                dos.writeInt(nonce.length);
                dos.write(nonce);
                break;

            default:
                throw new IllegalArgumentException("Algoritmo inválido");
        }

        return new CryptoInfo(key, encryptedData);
    }
}