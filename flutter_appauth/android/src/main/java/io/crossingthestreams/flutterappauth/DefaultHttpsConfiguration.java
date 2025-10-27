package io.crossingthestreams.flutterappauth;

import android.content.Context;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.connectivity.ConnectionBuilder;
import net.openid.appauth.connectivity.DefaultConnectionBuilder;

public class DefaultHttpsConfiguration extends HttpsConfiguration {
    public DefaultHttpsConfiguration() {
        super(Parameters.DEFAULT);
    }

    @Override
    public ConnectionBuilder getConnectionBuilder() {
        return DefaultConnectionBuilder.INSTANCE;
    }

    @Override
    protected AuthorizationService createAuthorizationService(Context context) {
        return new AuthorizationService(context);
    }
}
