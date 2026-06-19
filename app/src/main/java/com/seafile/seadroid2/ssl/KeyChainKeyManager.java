package com.seafile.seadroid2.ssl;

import android.content.Context;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.text.TextUtils;

import com.seafile.seadroid2.framework.util.SafeLogs;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.X509KeyManager;

/**
 * An {@link X509KeyManager} backed by the Android system KeyChain.
 * <p>
 * It presents the client certificate (and private key) identified by an alias when a
 * server requests client authentication (mTLS handshake). The private key never leaves
 * the OS keystore - we only hold a handle to it and the cryptographic operations are
 * performed by the keystore (possibly in hardware).
 * <p>
 * The alias is resolved through an {@link AliasProvider} on every handshake via
 * {@link #chooseClientAlias}. For a fixed binding pass a constant alias; for clients that
 * outlive an account switch (e.g. the shared Glide image pipeline) pass a provider that
 * looks up the current account's alias, so the right certificate is always presented.
 * Resolved keys / chains are cached per alias to avoid repeated KeyChain IPC.
 * <p>
 * {@link KeyChain#getPrivateKey} / {@link KeyChain#getCertificateChain} are blocking IPC
 * calls and must not run on the main thread; they are only ever invoked here from the
 * connection threads driving the TLS handshake.
 */
public class KeyChainKeyManager implements X509KeyManager {
    private static final String DEBUG_TAG = "KeyChainKeyManager";

    public interface AliasProvider {
        String getAlias();
    }

    private final Context context;
    private final AliasProvider aliasProvider;

    private final Map<String, X509Certificate[]> chainCache = new ConcurrentHashMap<>();
    private final Map<String, PrivateKey> keyCache = new ConcurrentHashMap<>();

    public KeyChainKeyManager(Context context, String alias) {
        this(context, () -> alias);
    }

    public KeyChainKeyManager(Context context, AliasProvider aliasProvider) {
        this.context = context.getApplicationContext();
        this.aliasProvider = aliasProvider;
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        String alias = aliasProvider.getAlias();
        return TextUtils.isEmpty(alias) ? null : alias;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        String alias = aliasProvider.getAlias();
        return TextUtils.isEmpty(alias) ? new String[0] : new String[]{alias};
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (TextUtils.isEmpty(alias)) {
            return null;
        }
        X509Certificate[] cached = chainCache.get(alias);
        if (cached != null) {
            return cached;
        }
        try {
            X509Certificate[] chain = KeyChain.getCertificateChain(context, alias);
            if (chain != null) {
                chainCache.put(alias, chain);
            }
            return chain;
        } catch (KeyChainException | InterruptedException e) {
            SafeLogs.e(DEBUG_TAG + ": unable to load certificate chain for alias " + alias + ", " + e.getMessage());
            return null;
        }
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (TextUtils.isEmpty(alias)) {
            return null;
        }
        PrivateKey cached = keyCache.get(alias);
        if (cached != null) {
            return cached;
        }
        try {
            PrivateKey key = KeyChain.getPrivateKey(context, alias);
            if (key != null) {
                keyCache.put(alias, key);
            }
            return key;
        } catch (KeyChainException | InterruptedException e) {
            SafeLogs.e(DEBUG_TAG + ": unable to load private key for alias " + alias + ", " + e.getMessage());
            return null;
        }
    }

    // server-side methods, unused on a client
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return null;
    }
}
