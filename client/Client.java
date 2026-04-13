package client;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class Client {

    public static void main(String[] args) throws Exception {

        Scanner sc = new Scanner(System.in);

        while (true) {

            System.out.println("\n[1] Login\n[2] Registrar\n[0] Sair");
            int escolha = sc.nextInt();
            sc.nextLine();

            if (escolha == 0) break;

            Socket socket = new Socket("localhost", 12345);

            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

            System.out.print("User: ");
            String user = sc.nextLine();

            System.out.print("Pass: ");
            String pass = sc.nextLine();

            if (escolha == 2) {
                dos.writeUTF("REGISTER");
                dos.writeUTF(user);
                dos.writeUTF(pass);

                System.out.println(dis.readUTF());
                socket.close();
                continue;
            }

            dos.writeUTF("LOGIN");
            dos.writeUTF(user);
            dos.writeUTF(pass);
            dos.flush(); 

            if (!dis.readUTF().equals("LOGIN_OK")) {
                System.out.println("Login falhou");
                socket.close();
                continue;
            }

            // 🔐 receber chave do servidor
            int keySize = dis.readInt();
            byte[] serverKeyBytes = new byte[keySize];
            dis.readFully(serverKeyBytes);

            PublicKey serverPublicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(serverKeyBytes));

            // 🔐 gerar chave do cliente
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair clientKeyPair = gen.generateKeyPair();

            // 🔐 enviar chave do cliente
            byte[] clientKeyBytes = clientKeyPair.getPublic().getEncoded();
            dos.writeInt(clientKeyBytes.length);
            dos.write(clientKeyBytes);
            dos.flush();

            while (true) {

                System.out.println("\n[1] Upload\n[2] Download\n[3] List\n[0] Sair");
                int op = sc.nextInt();
                sc.nextLine();

                if (op == 0) break;

                if (op == 1) {

                    dos.writeUTF("UPLOAD");

                    System.out.print("Arquivo: ");
                    String path = sc.nextLine();
                    File file = new File(path);

                    Logger.log("Enviando arquivo " + file.getName());

                    byte[] data = Files.readAllBytes(file.toPath());

                    SecretKey aesKey = CryptoUtils.generateAESKey();
                    byte[] encryptedData = CryptoUtils.encryptAES(data, aesKey);

                    Cipher rsa = Cipher.getInstance("RSA");
                    rsa.init(Cipher.ENCRYPT_MODE, serverPublicKey);
                    byte[] encryptedKey = rsa.doFinal(aesKey.getEncoded());

                    dos.writeUTF(file.getName());

                    dos.writeInt(encryptedKey.length);
                    dos.write(encryptedKey);

                    dos.writeInt(encryptedData.length);
                    dos.write(encryptedData);

                    Logger.logBytes("Dados criptografados", encryptedData);
                    Logger.log("Arquivo Enviado!");

                    System.out.println(dis.readUTF());
                }

                if (op == 2) {

                    dos.writeUTF("DOWNLOAD");

                    System.out.print("Nome: ");
                    String name = sc.nextLine();
                    dos.writeUTF(name);

                    int keySize2 = dis.readInt();
                    byte[] encryptedKey = new byte[keySize2];
                    dis.readFully(encryptedKey);

                    Cipher rsa = Cipher.getInstance("RSA");
                    rsa.init(Cipher.DECRYPT_MODE, clientKeyPair.getPrivate());

                    
                    byte[] aesKeyBytes = rsa.doFinal(encryptedKey);
                    SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

                    int size = dis.readInt();
                    byte[] encryptedData = new byte[size];
                    dis.readFully(encryptedData);

                    Logger.log("Recebendo arquivo " + name);
                    Logger.logBytes("Dados criptografados", encryptedData);

                    byte[] data = CryptoUtils.decryptAES(encryptedData, aesKey);
                    Logger.logBytes("Dados descriptografados", data);

                    Files.write(Paths.get("download_" + name), data);

                    System.out.println("Download OK");
                }

                if (op == 3) {

                    dos.writeUTF("LIST");

                    while (true) {
                        String f = dis.readUTF();
                        if (f.equals("END")) break;
                        System.out.println(f);
                    }

                    Logger.log("Recebendo Lista de arquivos");
                }
            }

            socket.close();
        }

        sc.close();
    }
}