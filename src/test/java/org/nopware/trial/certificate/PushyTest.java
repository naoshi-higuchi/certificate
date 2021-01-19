package org.nopware.trial.certificate;

import com.eatthepath.pushy.apns.ApnsClient;
import com.eatthepath.pushy.apns.ApnsClientBuilder;
import com.eatthepath.pushy.apns.util.ApnsPayloadBuilder;
import com.eatthepath.pushy.apns.util.SimpleApnsPayloadBuilder;
import com.eatthepath.pushy.apns.util.SimpleApnsPushNotification;
import com.eatthepath.pushy.apns.util.TokenUtil;
import lombok.val;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLException;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.nopware.trial.certificate.CertUtil.*;

public class PushyTest {
    @Test
    public void test() throws SSLException, ExecutionException, InterruptedException, TimeoutException {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate clientCACertificate = deserializeFromPEM(new String(read("client_ca_cert.pem")));
        PrivateKey clientCAKey = deserializePrivateKeyFromPEM(new String(read("client_ca_key.pem")));

        Instant notBefore = Instant.now();
        Instant notAfter = Instant.now().plus(Duration.ofSeconds(30));

        KeyPair clientKeyPair = generateKeyPair();
        X509Certificate clientCertificate = createEECertificate(clientCACertificate, clientCAKey, "CN=short_client", notBefore, notAfter, clientKeyPair.getPublic());

        ApnsClient apnsClient = new ApnsClientBuilder()
                .setApnsServer("localhost", 443)
                .setClientCredentials(clientCertificate, clientKeyPair.getPrivate(), null)
                .setTrustedServerCertificateChain(Paths.get("server_cert.pem").toFile())
                .build();

        ApnsPayloadBuilder payloadBuilder = new SimpleApnsPayloadBuilder();
        payloadBuilder.setAlertBody("Hello world!");
        SimpleApnsPushNotification notification =
                new SimpleApnsPushNotification(
                        TokenUtil.sanitizeTokenString("<dummy>"),
                        "org.nopware.trial.certificate",
                        payloadBuilder.build());

        val sendFuture = apnsClient.sendNotification(notification);
        sendFuture.get(1000L, TimeUnit.MILLISECONDS);
    }
}
