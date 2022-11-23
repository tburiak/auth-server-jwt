package com.course.springboot.auth.server.authserver.config.keys;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

@Component
public class KeyManager {
    private static final String KEY_PAIR_PRIVATE_KEY = "KeyPair/privateKey";
    private static final String KEY_PAIR_PUBLIC_KEY = "KeyPair/publicKey";

    public RSAKey rsaKey() throws Exception {

        RSAPublicKey publicKey = (RSAPublicKey) getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) getPrivate();

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    private PrivateKey getPrivate() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(KeyManager.KEY_PAIR_PRIVATE_KEY).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    public PublicKey getPublic() throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(KeyManager.KEY_PAIR_PUBLIC_KEY).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }


}
