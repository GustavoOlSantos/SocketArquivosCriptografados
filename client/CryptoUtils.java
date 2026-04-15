package client;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;

public class CryptoUtils {

    // ================= HASH =================
    public static String hashSHA256(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    // ================= AES =================
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static byte[] encryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // ================= DES =================
    public static SecretKey generateDESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        return keyGen.generateKey();
    }

    public static byte[] encryptDES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptDES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // ================= CHACHA20 =================
    public static SecretKey generateChaChaKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
        return keyGen.generateKey();
    }

    public static byte[] encryptChaCha(byte[] data, SecretKey key, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, 1);
        cipher.init(Cipher.ENCRYPT_MODE, key, param);
        return cipher.doFinal(data);
    }

    public static byte[] decryptChaCha(byte[] data, SecretKey key, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, 1);
        cipher.init(Cipher.DECRYPT_MODE, key, param);
        return cipher.doFinal(data);
    }
}