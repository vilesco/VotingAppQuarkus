package service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import model.User;
import org.jboss.logging.Logger;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@ApplicationScoped
public class DigitalSignatureService {
    @Inject
    Logger logger;

//    public boolean verifySignature(String data, String signature) {
//        try {
//            Signature sig = Signature.getInstance("SHA256withRSA");
//            PublicKey publicKey = loadPublicKey(data.split(":")[0]); // Assuming data format is "username:vote"
//            sig.initVerify(publicKey);
//            sig.update(data.getBytes());
//            return sig.verify(Base64.getDecoder().decode(signature));
//        } catch (Exception e) {
//            logger.error("Error verifying signature", e);
//            return false;
//        }
//    }

    public boolean verifySignature(String username, String data, String signature) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            PublicKey publicKey = loadPublicKey(username);
            sig.initVerify(publicKey);
            sig.update(data.getBytes());
            return sig.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            logger.error("Error verifying signature", e);
            return false;
        }
    }

//    private PublicKey loadPublicKey(String username) throws Exception {
//        User user = User.find("username", username).firstResult();
//        if (user == null || user.publicKey == null) {
//            throw new Exception("Public key not found for user: " + username);
//        }
//        byte[] publicKeyBytes = Base64.getDecoder().decode(user.publicKey);
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        return kf.generatePublic(spec);
//    }

    private PublicKey loadPublicKey(String username) throws Exception {
        User user = User.find("username", username).firstResult();
        if (user == null || user.publicKey == null) {
            throw new Exception("Public key not found for user: " + username);
        }
        byte[] publicKeyBytes = Base64.getDecoder().decode(user.publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
