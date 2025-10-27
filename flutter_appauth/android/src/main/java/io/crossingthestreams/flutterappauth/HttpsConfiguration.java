package io.crossingthestreams.flutterappauth;

import android.content.Context;
import android.util.Base64;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.connectivity.ConnectionBuilder;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public abstract class HttpsConfiguration {
    abstract public ConnectionBuilder getConnectionBuilder();
    abstract protected AuthorizationService createAuthorizationService(Context context);

    private final Parameters parameters;
    private AuthorizationService authorizationService;

    public HttpsConfiguration(Parameters parameters) {
        this.parameters = parameters;
    }

    public Parameters getParameters() {
        return parameters;
    }

    public AuthorizationService getAuthorizationService() {
        return authorizationService;
    }

    public void setContext(Context context) {
        dispose();
        authorizationService = createAuthorizationService(context);
    }

    public void dispose() {
        if (authorizationService != null) {
            try {
                authorizationService.dispose();
            } finally {
                authorizationService = null;
            }
        }
    }

    public static class Parameters {
        public static final Parameters DEFAULT = new Parameters(false, "", true);
        public static final Parameters INSECURE = new Parameters(true, "", true);

        public final boolean allowInsecureConnections;
        public final String customCaCertificates;
        public final boolean includePublicRootCaCertificates;
        public final List<X509Certificate> parsedCustomCaCertificates;

        public Parameters(boolean allowInsecureConnections, String customCaCertificates, boolean includePublicRootCaCertificates) {
            this.allowInsecureConnections = allowInsecureConnections;
            this.customCaCertificates = customCaCertificates;
            this.includePublicRootCaCertificates = includePublicRootCaCertificates;
            this.parsedCustomCaCertificates = parseCustomCaX509Certificates();
        }

        private List<X509Certificate> parseCustomCaX509Certificates() {
            if (customCaCertificates == null || customCaCertificates.isEmpty()) {
                return List.of();
            }

            String[] certificates = this.customCaCertificates.trim().split("\\s*\\|\\s*");
            List<X509Certificate> result = new ArrayList<>();
            for (String certificate: certificates) {
                if (certificate.isEmpty()) {
                    continue;
                }
                try {
                    String pemBody = certificate.replace("-----BEGIN CERTIFICATE-----", "")
                            .replace("-----END CERTIFICATE-----", "")
                            .replaceAll("\\s", "");

                    byte[] decoded = Base64.decode(pemBody, Base64.DEFAULT);
                    ByteArrayInputStream inputStream = new ByteArrayInputStream(decoded);
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
                    result.add(x509Certificate);
                } catch (CertificateException e) {
                    throw new RuntimeException("Error parsing certificate", e);
                }
            }
            return result;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Parameters)) return false;
            Parameters that = (Parameters) o;
            return allowInsecureConnections == that.allowInsecureConnections && includePublicRootCaCertificates == that.includePublicRootCaCertificates && Objects.equals(customCaCertificates, that.customCaCertificates);
        }
    }
}
