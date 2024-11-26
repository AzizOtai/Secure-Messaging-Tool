// File: RSAEncryption.java
import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSAEncryption {
    private KeyPair keyPair;

    /**
     * Generates an RSA key pair with a specified key size.
     *
     * @param keySize the size of the key (e.g., 2048).
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available.
     */
    public void generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        this.keyPair = keyGen.generateKeyPair();
        System.out.println("RSA Key Pair Generated.");
    }

    /**
     * Encrypts a plaintext message using the RSA public key.
     *
     * @param plainText the plaintext message to encrypt.
     * @return Base64 encoded ciphertext.
     * @throws Exception if encryption fails.
     */
    public String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.keyPair.getPublic());
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Message Encrypted.");
        return encryptedBase64;
    }

    /**
     * Decrypts a ciphertext message using the RSA private key.
     *
     * @param cipherTextBase64 the Base64 encoded ciphertext to decrypt.
     * @return the decrypted plaintext message.
     * @throws Exception if decryption fails.
     */
    public String decrypt(String cipherTextBase64) throws Exception {
        byte[] cipherBytes = Base64.getDecoder().decode(cipherTextBase64);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(cipherBytes);
        String decryptedText = new String(decryptedBytes, "UTF-8");
        System.out.println("Message Decrypted.");
        return decryptedText;
    }

    /**
     * Returns the public key in Base64 encoded string.
     *
     * @return Base64 encoded public key.
     */
    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded());
    }

    /**
     * Returns the private key in Base64 encoded string.
     *
     * @return Base64 encoded private key.
     */
    public String getPrivateKeyBase64() {
        return Base64.getEncoder().encodeToString(this.keyPair.getPrivate().getEncoded());
    }
}
