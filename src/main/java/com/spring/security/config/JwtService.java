package com.spring.security.config;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.security.Key;

@Service
public class JwtService {
    SecretKey JWT_SECRET = "";

    public String extractUsername(String token){
    return null;
    }

    private Claims extractAllClaims(String token) {
        return Jwts
            .parser()
            .verifyWith(JWT_SECRET)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    private Key getSignInKey() {
        return null;
    }

}
