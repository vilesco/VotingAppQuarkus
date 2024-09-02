package service;


import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.enterprise.context.ApplicationScoped;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

@ApplicationScoped
public class PasswordService {

    public String hashPassword(String password) {
        return BcryptUtil.bcryptHash(password);
    }

    public boolean verifyPassword(String plainText, String hashedPassword) {
        return BcryptUtil.matches(plainText, hashedPassword);
    }


    public String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];  // 128-bit salt
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // New method to derive an encryption key from the password and salt
    public String deriveKeyFromPassword(String password, String salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), Base64.getDecoder().decode(salt), 65536, 256);
        byte[] secretKey = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(secretKey);
    }
}
