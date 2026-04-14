package server;

import java.security.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    public static KeyPair keyPair;

    public static void main(String[] args) throws Exception {

        keyPair = KeyExchange.generateRSA();

        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Servidor rodando...");

        while (true) {
            Socket client = serverSocket.accept();
            new ClientHandler(client).start();
        }
    }
}