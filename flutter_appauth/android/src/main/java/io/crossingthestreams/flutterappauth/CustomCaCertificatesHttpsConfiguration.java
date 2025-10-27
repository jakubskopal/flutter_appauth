package io.crossingthestreams.flutterappauth;

import android.content.Context;
import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.connectivity.ConnectionBuilder;

import java.security.cert.X509Certificate;
import java.util.List;

public class CustomCaCertificatesHttpsConfiguration extends HttpsConfiguration {
    private final List<X509Certificate> customCaCertificates;
    private final ConnectionBuilder connectionBuilder;

    public CustomCaCertificatesHttpsConfiguration(Parameters parameters) {
        super(parameters);

        this.customCaCertificates = parameters.parsedCustomCaCertificates;
        this.connectionBuilder = new CustomCaCertificatesConnectionBuilder(customCaCertificates, parameters.includePublicRootCaCertificates);
    }

    @Override
    public ConnectionBuilder getConnectionBuilder() {
        return connectionBuilder;
    }

    @Override
    protected AuthorizationService createAuthorizationService(Context context) {
        AppAuthConfiguration.Builder authConfigBuilder = new AppAuthConfiguration.Builder();
        authConfigBuilder.setConnectionBuilder(connectionBuilder);
        return new AuthorizationService(context, authConfigBuilder.build());
    }
}
