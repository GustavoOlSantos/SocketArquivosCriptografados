package server;

import javax.crypto.SecretKey;

class CryptoInfo {
    public SecretKey key;
    public byte[] encryptedData;

    public CryptoInfo(SecretKey key, byte[] encryptedData) {
        this.key = key;
        this.encryptedData = encryptedData;
    }
}