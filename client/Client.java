package client;

import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

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

            PublicKey serverPublicKey = KeyExchange.receivePublicKey(dis);
            KeyPair clientKeyPair = KeyExchange.generateRSA();
            KeyExchange.sendPublicKey(dos, clientKeyPair.getPublic());

            KeyPair dhKeyPair = KeyExchange.generateDH();
            KeyExchange.sendDHPublicKey(dos, dhKeyPair.getPublic());
            PublicKey serverDhKey = KeyExchange.receiveDHPublicKey(dis);
            byte[] sharedSecret = KeyExchange.generateSharedSecret(dhKeyPair.getPrivate(), serverDhKey);

            Logger.logBytes("Chave Pública Diffie-Hellman do usuário " + user, sharedSecret);

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
                    Logger.logBytes("Dados", data);

                    CryptoInfo cryptoInfo = escolheAlgoritmoECriptografa(dos, sc, data);
                    byte[] encryptedKey = KeyExchange.encryptRSA(cryptoInfo.key.getEncoded(), serverPublicKey);

                    dos.writeUTF(file.getName());

                    dos.writeInt(encryptedKey.length);
                    dos.write(encryptedKey);

                    dos.writeInt(cryptoInfo.encryptedData.length);
                    dos.write(cryptoInfo.encryptedData);

                    Logger.logBytes("Dados criptografados", cryptoInfo.encryptedData);
                    Logger.log("Arquivo Enviado!");

                    System.out.println(dis.readUTF());
                }

                if (op == 2) {

                    dos.writeUTF("DOWNLOAD");

                    System.out.print("Nome: ");
                    String name = sc.nextLine();
                    dos.writeUTF(name);

                    int alg = escolheAlgoritmo(dos, sc);

                    byte[] nonce = null;
                    if (alg == 3) {
                        int nonceSize = dis.readInt();
                        nonce = new byte[nonceSize];
                        dis.readFully(nonce);
                    }

                    int keySize = dis.readInt();
                    byte[] encryptedKey = new byte[keySize];
                    dis.readFully(encryptedKey);

                    byte[] keyBytes = KeyExchange.decryptRSA(encryptedKey, clientKeyPair.getPrivate());

                    int size = dis.readInt();
                    byte[] encryptedData = new byte[size];
                    dis.readFully(encryptedData);

                    Logger.log("Recebendo arquivo " + name);
                    Logger.logBytes("Dados criptografados", encryptedData);

                    byte[] data = decriptaDados(alg, encryptedData, keyBytes, nonce);
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

    private static CryptoInfo escolheAlgoritmoECriptografa(DataOutputStream dos, Scanner sc, byte[] data) throws IOException {
        SecretKey key;
        byte[] encryptedData;

        int alg = escolheAlgoritmo(dos, sc);
        byte[] nonce = null;
        
        try{
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
                    Logger.log("Algoritmo inválido, escolhendo AES por padrão");
                    key = CryptoUtils.generateAESKey();
                    encryptedData = CryptoUtils.encryptAES(data, key);
            }
        } catch (Exception e){
            Logger.log("Erro ao gerar chave, encerrando conexão...");
            throw new RuntimeException(e);
        }
        
        return new CryptoInfo(key, encryptedData);
    }

    private static byte[] decriptaDados(int alg, byte[] encryptedData, byte[] keyBytes, byte[] nonce) throws Exception {
        switch (alg) {
            case 1:
                return CryptoUtils.decryptAES(encryptedData, new SecretKeySpec(keyBytes, "AES"));
            case 2:
                return CryptoUtils.decryptDES(encryptedData, new SecretKeySpec(keyBytes, "DES"));
            case 3:
                return CryptoUtils.decryptChaCha(encryptedData, new SecretKeySpec(keyBytes, "ChaCha20"), nonce);
            default:
                throw new IllegalArgumentException("Algoritmo inválido");
        }
    }

    private static int escolheAlgoritmo(DataOutputStream dos, Scanner sc) throws IOException {
        System.out.println("Escolha o algoritmo:");
        System.out.println("1 - AES");
        System.out.println("2 - DES");
        System.out.println("3 - ChaCha20");

        int alg = sc.nextInt();
        sc.nextLine();
        dos.writeInt(alg);

        return alg;    }
}