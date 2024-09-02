package service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@ApplicationScoped
public class KeyPairService {

    @Inject
    Logger logger;

//    public String generateAndStoreKeyPair(String username) {
//        try {
//            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//            keyGen.initialize(2048);
//            KeyPair pair = keyGen.generateKeyPair();
//            PublicKey publicKey = pair.getPublic();
//            PrivateKey privateKey = pair.getPrivate();
//
//            // Store the private key securely (this is just an example, not for production use)
//            String encodedPrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
//            // In a real application, you would store this securely, not in a file
//            // For demonstration purposes only:
//            // Files.write(Paths.get(username + "_private.key"), encodedPrivateKey.getBytes());
//
//            logger.info("Key pair generated for user: " + username);
//            return Base64.getEncoder().encodeToString(publicKey.getEncoded());
//        } catch (Exception e) {
//            logger.error("Error generating key pair for user: " + username, e);
//            throw new RuntimeException("Error generating key pair", e);
//        }
//    }

    //------------------------------------------------------------------------

    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 16 * 8; // 16 bytes (128 bits)
    private static final int GCM_IV_LENGTH = 12; // 12 bytes (96 bits)

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public String sign(String privateKeyString, String data) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }


    public String encryptPrivateKey(String keyForEncryption, String privateKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//        SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(keyForEncryption), "AES");
//        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
//        byte[] encrypted = cipher.doFinal(privateKey.getBytes());
//        return Base64.getEncoder().encodeToString(encrypted);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);

        // Generate a secure random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(keyForEncryption), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        byte[] encrypted = cipher.doFinal(privateKey.getBytes());

        logger.info("Encryption IV: " + Base64.getEncoder().encodeToString(iv));
        logger.info("Encrypted Data: " + Base64.getEncoder().encodeToString(encrypted));

        // Return IV + encrypted data (IV is needed for decryption)
        byte[] encryptedWithIv = new byte[GCM_IV_LENGTH + encrypted.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, GCM_IV_LENGTH);
        System.arraycopy(encrypted, 0, encryptedWithIv, GCM_IV_LENGTH, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    public String decryptPrivateKey(String keyForDecryption, String encryptedPrivateKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//        SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(keyForDecryption), "AES");
//        cipher.init(Cipher.DECRYPT_MODE, keySpec);
//        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedPrivateKey));
//        return new String(decrypted);

        try {


            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedPrivateKey);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encrypted = new byte[encryptedWithIv.length - GCM_IV_LENGTH];

            System.arraycopy(encryptedWithIv, 0, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(encryptedWithIv, GCM_IV_LENGTH, encrypted, 0, encrypted.length);

            // Log IV and ciphertext
            logger.info("IV: " + Base64.getEncoder().encodeToString(iv));
            logger.info("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));



            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(keyForDecryption), "AES");
            // Log derived key
            logger.info("Decryption Key: " + Base64.getEncoder().encodeToString(keySpec.getEncoded()));




            logger.info("Decryption IV: " + Base64.getEncoder().encodeToString(iv));
            logger.info("Encrypted Data (for decryption): " + Base64.getEncoder().encodeToString(encrypted));
            logger.info("Derived Key (for decryption): " + Base64.getEncoder().encodeToString(Base64.getDecoder().decode(keyForDecryption)));


            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decrypted = cipher.doFinal(encrypted);

            logger.info("Decrypted Data: " + new String(decrypted));

            return new String(decrypted);
        } catch (Exception e){
            logger.error("Decryption failed: " + e.getMessage(), e);
            throw e;
        }
        
    }

}
