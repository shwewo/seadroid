package com.seafile.seadroid2.ssl;

import android.text.TextUtils;

import com.google.common.collect.Maps;
import com.seafile.seadroid2.account.Account;
import com.seafile.seadroid2.framework.datastore.DataStoreKeys;
import com.seafile.seadroid2.preferences.Settings;

import java.util.Map;

/**
 * Stores, per account, the alias of the client certificate (mTLS) the user picked
 * from the Android system KeyChain.
 * <p>
 * The alias is keyed by the account signature (server + email), so the binding is
 * truly per-account: two accounts on the same server may use different client
 * certificates, and the same physical certificate may be shared by several accounts.
 * <p>
 * Only the alias is persisted here. The private key and certificate chain stay inside
 * the OS KeyChain and are resolved on demand by {@link KeyChainKeyManager}.
 */
public final class ClientCertManager {

    private final Map<String, String> cachedAliases = Maps.newConcurrentMap();

    private static ClientCertManager instance;

    public static synchronized ClientCertManager instance() {
        if (instance == null) {
            instance = new ClientCertManager();
        }
        return instance;
    }

    private static String prefKey(Account account) {
        // getEncryptSignature() == MD5(server + email), unique per account
        return DataStoreKeys.KEY_CLIENT_CERT_ALIAS + "_" + account.getEncryptSignature();
    }

    public void saveAlias(final Account account, final String alias) {
        if (account == null) {
            return;
        }

        if (TextUtils.isEmpty(alias)) {
            deleteAlias(account);
            return;
        }

        cachedAliases.put(account.getEncryptSignature(), alias);
        Settings.getCommonPreferences().edit().putString(prefKey(account), alias).apply();

        // drop any cached SSL factory built without (or with a different) client cert
        SSLTrustManager.instance().invalidate(account);
    }

    public void deleteAlias(final Account account) {
        if (account == null) {
            return;
        }

        cachedAliases.remove(account.getEncryptSignature());
        Settings.getCommonPreferences().edit().remove(prefKey(account)).apply();

        SSLTrustManager.instance().invalidate(account);
    }

    public String getAlias(final Account account) {
        if (account == null) {
            return null;
        }

        String cached = cachedAliases.get(account.getEncryptSignature());
        if (!TextUtils.isEmpty(cached)) {
            return cached;
        }

        String alias = Settings.getCommonPreferences().getString(prefKey(account), null);
        if (!TextUtils.isEmpty(alias)) {
            cachedAliases.put(account.getEncryptSignature(), alias);
        }
        return alias;
    }

    public boolean hasClientCert(final Account account) {
        return !TextUtils.isEmpty(getAlias(account));
    }
}
