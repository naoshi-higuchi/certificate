package org.nopware.trial.certificate;

import lombok.extern.slf4j.Slf4j;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.http.conn.ssl.StrictHostnameVerifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.nopware.trial.certificate.CertUtil.*;

@Slf4j
public class MyTest {
    private static final String CLIENT_KEY_PASSWORD = "I don't know how to skip encryption.";
    @Test
    public void test() throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate clientCertificate = deserializeFromPEM(new String(read("long_client_cert.pem")));
        PrivateKey privateKey = deserializePrivateKeyFromPEM(new String(read("long_client_key.pem")));
        KeyManagerFactory keyManagerFactory = keyManagerFactory(clientCertificate, privateKey);

        X509Certificate caCertificate = deserializeFromPEM(new String(read("server_ca_cert.pem")));
        TrustManagerFactory trustManagerFactory = trustManagerFactory(caCertificate);

        SSLContext sslContext = sslContext(keyManagerFactory, trustManagerFactory);

        OkHttpClient client = new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagerFactory.getTrustManagers()[0])
                .hostnameVerifier(new StrictHostnameVerifier())
                .addNetworkInterceptor(new Interceptor() {
                    @NotNull
                    @Override
                    public Response intercept(@NotNull Chain chain) throws IOException {
                        log.info("connection: {}", System.identityHashCode(chain.connection()));
                        Response response = chain.proceed(chain.request());
                        return response;
                    }
                })
                .build();

        Request request = new Request.Builder()
                .get()
                .url("https://localhost/")
                .build();

        Response response = client.newCall(request).execute();
        log.info("response body: {}", response.body().string());
        assertThat(response.code()).isEqualTo(200);

        for (int i = 0; i < 10; ++i) {
            Response r = client.newCall(request).execute();
            log.info("r.code(): {}", r.code());
        }
    }

    private static SSLContext sslContext(KeyManagerFactory keyManagerFactory, TrustManagerFactory trustManagerFactory) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyManagerFactory keyManagerFactory(X509Certificate clientCertificate, PrivateKey clientKey) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore(clientCertificate, clientKey), CLIENT_KEY_PASSWORD.toCharArray());
            return keyManagerFactory;
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static TrustManagerFactory trustManagerFactory(X509Certificate... caCertificates) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            for (X509Certificate certificate : caCertificates) {
                trustManagerFactory.init(keyStore(certificate));
            }
            return trustManagerFactory;
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyStore keyStore(X509Certificate caCertificate) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry(caCertificate.getSubjectX500Principal().getName(), caCertificate);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyStore keyStore(X509Certificate clientCertificate, PrivateKey clientKey) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setKeyEntry("client", convertToPKCS8(clientKey), new Certificate[] { clientCertificate });
            return keyStore;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] convertToPKCS8(PrivateKey privateKey) {
        try  {
            PKCS8EncryptedPrivateKeyInfoBuilder pkcs8Builder = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey);
            PKCS8EncryptedPrivateKeyInfo build = pkcs8Builder.build(
                    new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(CLIENT_KEY_PASSWORD.toCharArray()));
            return build.getEncoded();
        } catch (IOException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }
}
