package server;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

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

                // 🔐 ENVIAR chave do servidor
                byte[] serverKey = Server.keyPair.getPublic().getEncoded();
                dos.writeInt(serverKey.length);
                dos.write(serverKey);
                dos.flush();

                // 🔐 AGORA receber chave do cliente
                int keySize = dis.readInt();
                byte[] clientKeyBytes = new byte[keySize];
                dis.readFully(clientKeyBytes);

                clientPublicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(clientKeyBytes));
            }

            while (true) {

                String cmd = dis.readUTF();

                if (cmd.equals("UPLOAD")) {

                    String fileName = dis.readUTF();

                    int keySize = dis.readInt();
                    byte[] encryptedKey = new byte[keySize];
                    dis.readFully(encryptedKey);

                    Cipher rsa = Cipher.getInstance("RSA");
                    rsa.init(Cipher.DECRYPT_MODE, Server.keyPair.getPrivate());

                    byte[] aesKeyBytes = rsa.doFinal(encryptedKey);
                    SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

                    int size = dis.readInt();
                    byte[] encryptedData = new byte[size];
                    dis.readFully(encryptedData);

                    Logger.log("Recebendo arquivo " + fileName + " do usuário " + currentUser);
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

                    SecretKey aesKey = CryptoUtils.generateAESKey();
                    byte[] encryptedData = CryptoUtils.encryptAES(data, aesKey);

                    Cipher rsa = Cipher.getInstance("RSA");
                    rsa.init(Cipher.ENCRYPT_MODE, clientPublicKey);

                    byte[] encryptedKey = rsa.doFinal(aesKey.getEncoded());

                    dos.writeInt(encryptedKey.length);
                    dos.write(encryptedKey);

                    dos.writeInt(encryptedData.length);
                    dos.write(encryptedData);
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
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}