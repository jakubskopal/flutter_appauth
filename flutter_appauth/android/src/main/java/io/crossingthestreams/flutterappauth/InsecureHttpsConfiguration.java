package io.crossingthestreams.flutterappauth;

import android.content.Context;
import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.connectivity.ConnectionBuilder;

public class InsecureHttpsConfiguration extends HttpsConfiguration {
    public InsecureHttpsConfiguration() {
        super(Parameters.INSECURE);
    }

    @Override
    public ConnectionBuilder getConnectionBuilder() {
        return InsecureConnectionBuilder.INSTANCE;
    }

    @Override
    protected AuthorizationService createAuthorizationService(Context context) {
        AppAuthConfiguration.Builder authConfigBuilder = new AppAuthConfiguration.Builder();
        authConfigBuilder.setConnectionBuilder(InsecureConnectionBuilder.INSTANCE);
        authConfigBuilder.setSkipIssuerHttpsCheck(true);
        return new AuthorizationService(context, authConfigBuilder.build());
    }
}
