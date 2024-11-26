import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSAEncryption {
    private KeyPair keyPair;

    public void generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        this.keyPair = keyGen.generateKeyPair();
        System.out.println("RSA Key Pair Generated.");
    }


    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.keyPair.getPublic());
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Message Encrypted.");
        return encryptedBase64;
    }


    public String decrypt(String cipherTextBase64) throws Exception {
        byte[] cipherBytes = Base64.getDecoder().decode(cipherTextBase64);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(cipherBytes);
        String decryptedText = new String(decryptedBytes, "UTF-8");
        System.out.println("Message Decrypted.");
        return decryptedText;
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded());
    }

    public String getPrivateKeyBase64() {
        return Base64.getEncoder().encodeToString(this.keyPair.getPrivate().getEncoded());
    }
}
