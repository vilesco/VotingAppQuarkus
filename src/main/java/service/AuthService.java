package service;

import jakarta.enterprise.context.ApplicationScoped;
import model.User;
import io.smallrye.jwt.build.Jwt;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;


@ApplicationScoped
public class AuthService {
    public String generateToken(User user) {
        return Jwt.issuer("http://localhost:8080")
                .subject(user.username)
                .groups(new HashSet<>(Arrays.asList(user.role)))
                .expiresIn(Duration.ofHours(1))
                .sign();
    }
}
