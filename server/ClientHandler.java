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
            }

            while (true) {

                String cmd = dis.readUTF();

                if (cmd.equals("UPLOAD")) {

                    String fileName = dis.readUTF();
                    Logger.log("Recebendo arquivo " + fileName + " do usuário " + currentUser);

                    int keySize = dis.readInt();
                    byte[] encryptedKey = new byte[keySize];
                    dis.readFully(encryptedKey);

                    byte[] aesKeyBytes = KeyExchange.decryptRSA(encryptedKey, Server.keyPair.getPrivate());
                    SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

                    int size = dis.readInt();
                    byte[] encryptedData = new byte[size];
                    dis.readFully(encryptedData);
                    Logger.logBytes("Dados criptografados", encryptedData);
                    
                    byte[] data = CryptoUtils.decryptAES(encryptedData, aesKey);
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

                    Logger.log("Recebendo pedido de download do arquivo " + fileName);
                    Logger.log("Com chave Pública: " + clientPublicKey);

                    byte[] data = Files.readAllBytes(Paths.get("server/files/" + fileName));
                    Logger.logBytes("Dados Originais", data);

                    SecretKey aesKey = CryptoUtils.generateAESKey();
                    byte[] encryptedData = CryptoUtils.encryptAES(data, aesKey);
                    Logger.logBytes("Dados criptografados", encryptedData);

                    byte[] encryptedKey = KeyExchange.encryptRSA(aesKey.getEncoded(), clientPublicKey);

                    dos.writeInt(encryptedKey.length);
                    dos.write(encryptedKey);

                    dos.writeInt(encryptedData.length);
                    dos.write(encryptedData);
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
}