
package com.seafile.seadroid2.framework.http;

import com.blankj.utilcode.util.CollectionUtils;
import com.seafile.seadroid2.SeadroidApplication;
import com.seafile.seadroid2.account.Account;
import com.seafile.seadroid2.account.SupportAccountManager;
import com.seafile.seadroid2.ssl.ClientCertManager;
import com.seafile.seadroid2.ssl.KeyChainKeyManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.ConnectionSpec;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;

public class UnsafeOkHttpClient extends BaseOkHttpClient {
    private final List<Interceptor> _interceptors = new ArrayList<>();
    public UnsafeOkHttpClient() {
        super(null);

        _interceptors.clear();
        _interceptors.addAll(getInterceptors());
    }
    public UnsafeOkHttpClient(Account account) {
        super(account);

        _interceptors.clear();
        _interceptors.addAll(getInterceptors());
    }

    private final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[]{};
        }
    }
    };

    /**
     * Client certificate (mTLS) key managers. The alias is resolved per-handshake from
     * the bound account, or - when this client has no account (e.g. the shared Glide
     * pipeline) - from whichever account is currently logged in. Returns {@code null}
     * when no client certificate is configured, leaving an ordinary TLS connection.
     */
    private KeyManager[] getKeyManagers() {
        return new KeyManager[]{new KeyChainKeyManager(SeadroidApplication.getAppContext(), () -> {
            Account account = specialAccount != null
                    ? specialAccount
                    : SupportAccountManager.getInstance().getCurrentAccount();
            return account == null ? null : ClientCertManager.instance().getAlias(account);
        })};
    }

    public OkHttpClient.Builder getBuilder() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();


        try {
            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(getKeyManagers(), trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }

        builder.connectionSpecs(Arrays.asList(
                ConnectionSpec.MODERN_TLS,
                ConnectionSpec.COMPATIBLE_TLS,
                ConnectionSpec.CLEARTEXT));
        builder.cache(cache);
        builder.hostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
        //cache control
//        builder.interceptors().add(REWRITE_CACHE_CONTROL_INTERCEPTOR);
//        builder.networkInterceptors().add(REWRITE_CACHE_CONTROL_INTERCEPTOR);

        //add interceptors
        if (!CollectionUtils.isEmpty(_interceptors)) {
            for (Interceptor i : _interceptors) {
                builder.interceptors().add(i);
            }
        }

        //timeout
        builder.writeTimeout(DEFAULT_TIME_OUT, TimeUnit.MILLISECONDS);
        builder.readTimeout(DEFAULT_TIME_OUT, TimeUnit.MILLISECONDS);
        builder.connectTimeout(DEFAULT_TIME_OUT, TimeUnit.MILLISECONDS);

        return builder;
    }

    public OkHttpClient getOkClient() {
        OkHttpClient.Builder builder = getBuilder();
        return builder.build();
    }


}