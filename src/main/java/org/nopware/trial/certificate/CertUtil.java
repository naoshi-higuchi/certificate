package org.nopware.trial.certificate;

import javaslang.control.Try;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Hello world!
 */
@Slf4j
public class CertUtil {
    public static void main(String[] args) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());

        KeyPair keyPair = generateKeyPair();
        PKCS10CertificationRequest pkcs10CertificationRequest = createPKCS10CertificationRequest(keyPair, "www.example.com");

        KeyPair caKeyPair = generateKeyPair();
        KeyPair eeKeyPair = generateKeyPair();
        Instant notBefore = Instant.now();
        Instant notAfter = Instant.now().plus(Duration.ofHours(1));
        X509Certificate caCertificate = createCACertificate(caKeyPair, "CN=MyIssuer", notBefore, notAfter);
        log.info("CA certificate: {}", caCertificate.toString());
        String caCertificatePEM = serializeToPEM(caCertificate);
        log.info("CA certificate in PEM: {}", caCertificatePEM);
        X509Certificate eeCertificate = createEECertificate(caCertificate, caKeyPair.getPrivate(), "CN=localhost", notBefore, notAfter, eeKeyPair.getPublic());
        log.info("localhost certificate: {}", eeCertificate);
        String certificatePEM = serializeToPEM(eeCertificate);
        log.info("localhost certificate in PEM: {}", certificatePEM);

        Try<PKIXCertPathValidatorResult> tryResult = validateCertPath(Arrays.asList(eeCertificate), caCertificate);
        tryResult.andThen(result -> log.info("Valid: {}", result.toString()))
                .orElseRun(throwable -> log.error("Invalid.", throwable));
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static ContentSigner createContentSigner(PrivateKey privateKey) {
        try {
            return new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create CSR.
     * CSR: Certificate Signing Request (or CR: Certification Request)
     *
     * @param keyPair
     * @return
     */
    public static PKCS10CertificationRequest createPKCS10CertificationRequest(KeyPair keyPair, String cn) {
        ContentSigner contentSigner = createContentSigner(keyPair.getPrivate());
        return new JcaPKCS10CertificationRequestBuilder(
                new X500Name(String.format("CN=%s", cn)), keyPair.getPublic())
                .build(contentSigner);
    }

    public static X509Certificate createEECertificate(X509Certificate caCertificate, PrivateKey caPrivateKey, String eeDN, Instant notBefore, Instant notAfter, PublicKey eePublicKey) {
        X509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(
                caCertificate.getSubjectX500Principal(),
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(notBefore.toEpochMilli()),
                new Date(notAfter.toEpochMilli()),
                new X500Principal(eeDN),
                eePublicKey);
        try {
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(builder.build(createContentSigner(caPrivateKey)));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate createCACertificate(KeyPair caKeyPair, String caDN, Instant notBefore, Instant notAfter) {
        X509v1CertificateBuilder builder = new JcaX509v1CertificateBuilder(
                new X500Name(caDN),
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(notBefore.toEpochMilli()),
                new Date(notAfter.toEpochMilli()),
                new X500Name(caDN),
                caKeyPair.getPublic());
        try {
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(builder.build(createContentSigner(caKeyPair.getPrivate())));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static String serializeToPEM(X509Certificate certificate) {
        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificate);
            pemWriter.flush();
            pemWriter.close();
            return stringWriter.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate deserializeFromPEM(String pem) {
        try (StringReader stringReader = new StringReader(pem);
             PEMParser pemParser = new PEMParser(stringReader)) {
            X509CertificateHolder certificateHolder = (X509CertificateHolder) pemParser.readObject();
            return new JcaX509CertificateConverter().getCertificate(certificateHolder);
        } catch (IOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static String serializeToPEM(PrivateKey privateKey) {
        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(privateKey);
            pemWriter.flush();
            pemWriter.close();
            return stringWriter.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey deserializePrivateKeyFromPEM(String pem) {

        try (StringReader stringReader = new StringReader(pem);
             PEMParser pemParser = new PEMParser(stringReader)) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
            return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Try<PKIXCertPathValidatorResult> validateCertPath(List<X509Certificate> certChain, X509Certificate taCert) {
        return Try.of(() ->{
            try {
                CertPath certPath = CertificateFactory.getInstance("X.509").generateCertPath(certChain);
                Set<TrustAnchor> trustAnchorSet = new HashSet<>();
                trustAnchorSet.add(new TrustAnchor(taCert, null));
                CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
                PKIXParameters param = new PKIXParameters(trustAnchorSet);
                param.setRevocationEnabled(false);
                param.setDate(new Date(Instant.now().toEpochMilli()));
                PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, param);
                return result;
            } catch (CertificateException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            }});
    }

    public static byte[] read(String path) {
        try {
            return Files.readAllBytes(Paths.get(path));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
