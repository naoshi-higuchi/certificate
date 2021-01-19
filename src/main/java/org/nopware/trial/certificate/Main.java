package org.nopware.trial.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

import static org.nopware.trial.certificate.CertUtil.*;

public class Main {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        Instant NOW = Instant.now();
        Instant LONG_AFTER = NOW.plus(Duration.ofDays(36500));
        Instant SHORT_AFTER = NOW.plus(Duration.ofSeconds(30));

        KeyPair serverCAKeyPair = generateKeyPair();
        X509Certificate serverCACertificate = createCACertificate(serverCAKeyPair, "CN=ServerCA", NOW, LONG_AFTER);
        String serverCACertificatePEM = serializeToPEM(serverCACertificate);
        write("server_ca_cert.pem", serverCACertificatePEM);

        KeyPair serverKeyPair = generateKeyPair();
        String serverKeyPem = serializeToPEM(serverKeyPair.getPrivate());
        write("server_key.pem", serverKeyPem);

        X509Certificate serverCertificate = createEECertificate(serverCACertificate, serverCAKeyPair.getPrivate(), "CN=localhost", NOW, LONG_AFTER, serverKeyPair.getPublic());
        String serverCertificatePem = serializeToPEM(serverCertificate);
        write("server_cert.pem", serverCertificatePem);

        KeyPair clientCAKeyPair = generateKeyPair();
        String clientCAKeyPem = serializeToPEM(clientCAKeyPair.getPrivate());
        write("client_ca_key.pem", clientCAKeyPem);

        X509Certificate clientCACertificate = createCACertificate(clientCAKeyPair, "CN=ClientCA", NOW, LONG_AFTER);
        String clientCACertificatePEM = serializeToPEM(clientCACertificate);
        write("client_ca_cert.pem", clientCACertificatePEM);

        KeyPair clientKeyPair = generateKeyPair();
        String clientKeyPem= serializeToPEM(clientKeyPair.getPrivate());
        write("long_client_key.pem", clientKeyPem);

        X509Certificate clientCertificate = createEECertificate(clientCACertificate, clientCAKeyPair.getPrivate(), "CN=longClient", NOW, LONG_AFTER, clientKeyPair.getPublic());
        String clientCertificatePEM = serializeToPEM(clientCertificate);
        write("long_client_cert.pem", clientCertificatePEM);

        KeyPair shortClientKeyPair = generateKeyPair();
        String shortClientKeyPem = serializeToPEM(shortClientKeyPair.getPrivate());
        write("short_client_key.pem", shortClientKeyPem);

        X509Certificate shortClientCertificate = createEECertificate(clientCACertificate, clientCAKeyPair.getPrivate(), "CN=shortClient", NOW, SHORT_AFTER, shortClientKeyPair.getPublic());
        String shortClientCertificatePEM = serializeToPEM(shortClientCertificate);
        write("short_client_cert.pem", shortClientCertificatePEM);
    }

    public static void write(String path, String content) throws IOException {
        Files.write(
                Paths.get(path),
                content.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
    }
}
