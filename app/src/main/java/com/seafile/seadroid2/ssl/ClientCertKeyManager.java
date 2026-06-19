package com.seafile.seadroid2.ssl;

import android.content.Context;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.text.TextUtils;

import com.seafile.seadroid2.account.Account;
import com.seafile.seadroid2.framework.util.SafeLogs;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

/**
 * An {@link X509KeyManager} that presents an account's client certificate (mTLS) during the
 * TLS handshake, supporting both binding sources handled by {@link ClientCertManager}:
 * <ul>
 *   <li><b>KeyChain</b> — resolved via the Android system keystore; the private key never
 *       leaves the OS.</li>
 *   <li><b>P12</b> — an imported file, loaded into an in-memory {@link KeyManagerFactory}
 *       whose result is cached.</li>
 * </ul>
 * The account (and therefore its binding) is resolved <b>per handshake</b> through an
 * {@link AccountProvider}, never baked in. This is deliberate: the resulting socket factory
 * is cached (in {@link SSLTrustManager}) and the OkHttpClient built from it is cached again
 * one layer up, so a baked-in cert could be presented stale until an app restart. Resolving
 * lazily means a cached factory always presents the account's current certificate.
 * <p>
 * If no certificate is bound, {@link #chooseClientAlias} returns {@code null} and no client
 * cert is sent — an ordinary one-way TLS connection.
 * <p>
 * The KeyChain / file calls are blocking; they only ever run here on the connection threads
 * driving the handshake, never the main thread.
 */
public class ClientCertKeyManager implements X509KeyManager {
    private static final String DEBUG_TAG = "ClientCertKeyManager";

    public interface AccountProvider {
        Account get();
    }

    private final Context context;
    private final AccountProvider accountProvider;

    // KeyChain caches, keyed by keychain alias
    private final Map<String, X509Certificate[]> kcChainCache = new ConcurrentHashMap<>();
    private final Map<String, PrivateKey> kcKeyCache = new ConcurrentHashMap<>();
    // p12 delegate cache, keyed by file path + last-modified
    private final Map<String, X509KeyManager> p12Cache = new ConcurrentHashMap<>();

    public ClientCertKeyManager(Context context, AccountProvider accountProvider) {
        this.context = context.getApplicationContext();
        this.accountProvider = accountProvider;
    }

    private Account account() {
        return accountProvider == null ? null : accountProvider.get();
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        Account account = account();
        if (account == null) {
            return null;
        }
        ClientCertManager.ClientCertBinding b = ClientCertManager.instance().getBinding(account);
        if (b == null) {
            return null;
        }
        if (b.type == ClientCertManager.Type.KEYCHAIN) {
            return TextUtils.isEmpty(b.alias) ? null : b.alias;
        }
        X509KeyManager km = p12Delegate(account, b);
        return km == null ? null : km.chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        String alias = chooseClientAlias(new String[]{keyType}, issuers, null);
        return alias == null ? new String[0] : new String[]{alias};
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        Account account = account();
        if (account == null) {
            return null;
        }
        ClientCertManager.ClientCertBinding b = ClientCertManager.instance().getBinding(account);
        if (b == null) {
            return null;
        }
        if (b.type == ClientCertManager.Type.KEYCHAIN) {
            return keychainChain(b.alias);
        }
        X509KeyManager km = p12Delegate(account, b);
        return km == null ? null : km.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        Account account = account();
        if (account == null) {
            return null;
        }
        ClientCertManager.ClientCertBinding b = ClientCertManager.instance().getBinding(account);
        if (b == null) {
            return null;
        }
        if (b.type == ClientCertManager.Type.KEYCHAIN) {
            return keychainKey(b.alias);
        }
        X509KeyManager km = p12Delegate(account, b);
        return km == null ? null : km.getPrivateKey(alias);
    }

    // ---- KeyChain ----

    private X509Certificate[] keychainChain(String alias) {
        if (TextUtils.isEmpty(alias)) {
            return null;
        }
        X509Certificate[] cached = kcChainCache.get(alias);
        if (cached != null) {
            return cached;
        }
        try {
            X509Certificate[] chain = KeyChain.getCertificateChain(context, alias);
            if (chain != null) {
                kcChainCache.put(alias, chain);
            }
            return chain;
        } catch (KeyChainException | InterruptedException e) {
            SafeLogs.e(DEBUG_TAG + ": keychain chain load failed for " + alias + ", " + e.getMessage());
            return null;
        }
    }

    private PrivateKey keychainKey(String alias) {
        if (TextUtils.isEmpty(alias)) {
            return null;
        }
        PrivateKey cached = kcKeyCache.get(alias);
        if (cached != null) {
            return cached;
        }
        try {
            PrivateKey key = KeyChain.getPrivateKey(context, alias);
            if (key != null) {
                kcKeyCache.put(alias, key);
            }
            return key;
        } catch (KeyChainException | InterruptedException e) {
            SafeLogs.e(DEBUG_TAG + ": keychain key load failed for " + alias + ", " + e.getMessage());
            return null;
        }
    }

    // ---- P12 ----

    private X509KeyManager p12Delegate(Account account, ClientCertManager.ClientCertBinding b) {
        if (b == null || TextUtils.isEmpty(b.p12Path)) {
            return null;
        }
        File f = new File(b.p12Path);
        if (!f.exists()) {
            return null;
        }
        String cacheKey = b.p12Path + "|" + f.lastModified();
        X509KeyManager cached = p12Cache.get(cacheKey);
        if (cached != null) {
            return cached;
        }
        try {
            String pwd = ClientCertManager.instance().getP12Password(account);
            char[] pc = pwd == null ? new char[0] : pwd.toCharArray();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = new FileInputStream(f)) {
                ks.load(in, pc);
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pc);
            for (KeyManager km : kmf.getKeyManagers()) {
                if (km instanceof X509KeyManager) {
                    p12Cache.put(cacheKey, (X509KeyManager) km);
                    return (X509KeyManager) km;
                }
            }
        } catch (Exception e) {
            SafeLogs.e(DEBUG_TAG + ": p12 load failed for " + b.p12Path + ", " + e.getMessage());
        }
        return null;
    }

    // ---- server-side, unused on a client ----

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return null;
    }
}
