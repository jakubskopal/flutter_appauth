package io.crossingthestreams.flutterappauth;

import android.net.Uri;
import androidx.annotation.NonNull;
import net.openid.appauth.Preconditions;
import net.openid.appauth.connectivity.ConnectionBuilder;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CustomCaCertificatesConnectionBuilder implements ConnectionBuilder {
    private final List<X509Certificate> customCaCertificates;
    private final boolean includePublicRootCaCertificates;

    public CustomCaCertificatesConnectionBuilder(List<X509Certificate> customCaCertificates, boolean includePublicRootCaCertificates) {
        this.customCaCertificates = customCaCertificates;
        this.includePublicRootCaCertificates = includePublicRootCaCertificates;
    }

    private static final int CONNECTION_TIMEOUT_MS = (int) TimeUnit.SECONDS.toMillis(15);
    private static final int READ_TIMEOUT_MS = (int) TimeUnit.SECONDS.toMillis(10);

    private static final String HTTPS_SCHEME = "https";

    @NonNull
    @Override
    public HttpURLConnection openConnection(@NonNull Uri uri) throws IOException {
        Preconditions.checkNotNull(uri, "url must not be null");
        Preconditions.checkArgument(HTTPS_SCHEME.equals(uri.getScheme()),
                "only https connections are permitted");
        HttpsURLConnection conn = (HttpsURLConnection) new URL(uri.toString()).openConnection();
        conn.setConnectTimeout(CONNECTION_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        conn.setInstanceFollowRedirects(false);
        conn.setSSLSocketFactory(createSSLSocketFactory());
        return conn;
    }

    private SSLSocketFactory createSSLSocketFactory() throws IOException {
        try {
            final X509TrustManager systemTrustManager = createKeystoreTrustManager(null);

            KeyStore caCertificatesKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caCertificatesKeyStore.load(null, null);
            for (int i = 0; i < customCaCertificates.size(); i++) {
                caCertificatesKeyStore.setCertificateEntry("ca_" + i, customCaCertificates.get(i));
            }
            final X509TrustManager caCertificatesTrustManager = createKeystoreTrustManager(caCertificatesKeyStore);

            X509TrustManager customTrustManager = new CombinedX509TrustManager(systemTrustManager, caCertificatesTrustManager);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{customTrustManager}, null);
            return sslContext.getSocketFactory();
        } catch (KeyStoreException | NoSuchAlgorithmException | KeyManagementException | CertificateException e) {
            throw new IOException("Error creating custom SSL Socket factory", e);
        }
    }

    private @NotNull X509TrustManager createKeystoreTrustManager(KeyStore keyStore) throws KeyStoreException, NoSuchAlgorithmException {
        final TrustManagerFactory systemTrustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        systemTrustManagerFactory.init(keyStore);
        return (X509TrustManager) systemTrustManagerFactory.getTrustManagers()[0];
    }

    private class CombinedX509TrustManager implements X509TrustManager {
        private final X509TrustManager systemTrustManager;
        private final X509TrustManager caCertificatesTrustManager;

        public CombinedX509TrustManager(X509TrustManager systemTrustManager, X509TrustManager caCertificatesTrustManager) {
            this.systemTrustManager = systemTrustManager;
            this.caCertificatesTrustManager = caCertificatesTrustManager;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            systemTrustManager.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                if (includePublicRootCaCertificates) {
                    systemTrustManager.checkServerTrusted(chain, authType);
                    return;
                }
            } catch (CertificateException e) {
                // Fall through to custom cert check
            }

            caCertificatesTrustManager.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            List<X509Certificate> list = new ArrayList<>(customCaCertificates);
            if (includePublicRootCaCertificates) {
                list.addAll(Arrays.asList(systemTrustManager.getAcceptedIssuers()));
            }
            return list.toArray(new X509Certificate[0]);
        }
    }
}
