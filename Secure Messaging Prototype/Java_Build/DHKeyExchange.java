// File: DHKeyExchange.java
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DHKeyExchange {
    private KeyPair keyPair;
    private SecretKey sharedSecret;

    public void generateDHKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(2048);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhSpec);
        this.keyPair = keyPairGen.generateKeyPair();
        System.out.println("DH Key Pair Generated.");
    }

    public void generateSharedSecret(byte[] peerPublicKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(peerPublicKeyBytes);
        PublicKey peerPublicKey = keyFactory.generatePublic(x509KeySpec);

        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(this.keyPair.getPrivate());
        keyAgree.doPhase(peerPublicKey, true);

        byte[] sharedSecretBytes = keyAgree.generateSecret();
        this.sharedSecret = new SecretKeySpec(sharedSecretBytes, 0, 16, "AES"); 
        System.out.println("Shared Secret Generated.");
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded());
    }


    public SecretKey getSharedSecret() {
        return this.sharedSecret;
    }


    public void printSharedSecretHex() {
        if (this.sharedSecret != null) {
            byte[] keyBytes = this.sharedSecret.getEncoded();
            StringBuilder sb = new StringBuilder();
            for (byte b : keyBytes) {
                sb.append(String.format("%02x", b));
            }
            System.out.println("Shared Secret (Hex): " + sb.toString());
        } else {
            System.out.println("Shared secret not generated yet.");
        }
    }
}
