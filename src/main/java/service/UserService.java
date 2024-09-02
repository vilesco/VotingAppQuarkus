package service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import model.LoginRequest;
import model.TokenResponse;
import model.User;
import org.jboss.logging.Logger;

import java.security.KeyPair;
import java.util.Base64;


@Path("/user")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserService {

    @Inject
    PasswordService passwordService;

    @Inject
    AuthService authService;

    @Inject
    Logger logger;

    @Inject
    KeyPairService keyPairService;

    @POST
    @Path("/register")
//    public Response register(@Valid User user) throws Exception {
//        try {
//            if (User.find("username", user.username).firstResult() != null) {
//                logger.warn("Registration attempt with existing username: " + user.username);
//                return Response.status(Response.Status.CONFLICT).entity("Username already exists").build();
//            }
//            user.password = passwordService.hashPassword(user.password);
//            user.publicKey = keyPairService.generateAndStoreKeyPair(user.username);
//            user.persist();
//            logger.info("New user registered: " + user.username);
//            return Response.status(Response.Status.CREATED).build();
//        } catch (Exception e) {
//            logger.error("Error during user registration", e);
//            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("An unexpected error occurred").build();
//        }
//    }
        //--------------------------------------------------------------------------------------

    public Response register(User user) throws Exception {
        try{
            if (User.find("username", user.username).firstResult() != null) {
                throw new Exception("Username already exists");
            }
            user.password = passwordService.hashPassword(user.password);

//        // Generate key pair
        KeyPair keyPair = keyPairService.generateKeyPair();
        user.publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
//
//        // Store the private key securely
//        String privateKeyString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
//        System.out.println("Private key for " + user.username + ": " + privateKeyString);
//
//        user.persist();
//        return user;

            // Generate salt and key for encrypting the private key
            String salt = passwordService.generateSalt();  // Generate a unique salt for the user
            String keyForEncryption = passwordService.deriveKeyFromPassword(user.password, salt);  // Derive encryption key

            // Encrypt and store the private key securely
            String privateKeyString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            String encryptedPrivateKey = keyPairService.encryptPrivateKey(keyForEncryption, privateKeyString);
            user.privateKey = encryptedPrivateKey;  // Store the encrypted private key
            user.salt = salt;  // Store the salt

            user.persist();
            logger.info("New user registered: " + user.username);
            return Response.status(Response.Status.CREATED).build();
        } catch (Exception e) {
            logger.error("Error during user registration", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("An unexpected error occurred").build();
        }

    }

    @POST
    @Path("/login")
    public Response login(@Valid LoginRequest loginRequest) {
        User user = User.find("username", loginRequest.username).firstResult();
        if (user != null && passwordService.verifyPassword(loginRequest.password, user.password)) {
            String token = authService.generateToken(user);
            logger.info("User logged in: " + user.username);
            return Response.ok(new TokenResponse(token)).build();
        }
        logger.warn("Failed login attempt for username: " + loginRequest.username);
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @POST
    @Path("/sign")
    public String sign(SignRequest signRequest) throws Exception {
        User user = User.find("username", signRequest.username).firstResult();
        if (user == null) {
            throw new Exception("User not found");
        }

        // Derive the encryption key from the password and salt
        String keyForDecryption = passwordService.deriveKeyFromPassword(signRequest.password, user.salt);
        String decryptedPrivateKey = keyPairService.decryptPrivateKey(keyForDecryption, user.privateKey);

        return keyPairService.sign(decryptedPrivateKey, signRequest.data);
//        return keyPairService.sign(signRequest.privateKey, signRequest.data);
//        decryptedPrivateKey
    }

    public static class SignRequest {
        public String username;
        public String password;
        public String privateKey;
        public String data;
    }

}
