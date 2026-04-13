package server;

import java.security.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    public static KeyPair keyPair;

    public static void main(String[] args) throws Exception {

        // 🔐 gerar chave RSA
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        keyPair = gen.generateKeyPair();

        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Servidor rodando...");

        while (true) {
            Socket client = serverSocket.accept();
            new ClientHandler(client).start();
        }
    }
}