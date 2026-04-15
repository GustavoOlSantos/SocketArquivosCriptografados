package server;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

public class KeyExchange {

    public static KeyPair generateRSA() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static byte[] encryptRSA(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static void sendPublicKey(DataOutputStream dos, PublicKey key) throws Exception {
        byte[] keyBytes = key.getEncoded();
        dos.writeInt(keyBytes.length);
        dos.write(keyBytes);
        dos.flush();
    }

    public static PublicKey receivePublicKey(DataInputStream dis) throws Exception {
        int size = dis.readInt();
        byte[] keyBytes = new byte[size];
        dis.readFully(keyBytes);

        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static KeyPair generateDH() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("DH");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static void sendDHPublicKey(DataOutputStream dos, PublicKey key) throws Exception {
        byte[] keyBytes = key.getEncoded();
        dos.writeInt(keyBytes.length);
        dos.write(keyBytes);
        dos.flush();
    }

    public static PublicKey receiveDHPublicKey(DataInputStream dis) throws Exception {
        int size = dis.readInt();
        byte[] keyBytes = new byte[size];
        dis.readFully(keyBytes);

        return KeyFactory.getInstance("DH")
                .generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        return ka.generateSecret();
    }
}