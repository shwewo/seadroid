package com.seafile.seadroid2.ssl;

import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Pair;

import com.blankj.utilcode.util.EncryptUtils;
import com.seafile.seadroid2.SeadroidApplication;
import com.seafile.seadroid2.account.Account;
import com.seafile.seadroid2.framework.crypto.SecurePasswordManager;
import com.seafile.seadroid2.framework.datastore.DataStoreKeys;
import com.seafile.seadroid2.framework.util.SafeLogs;
import com.seafile.seadroid2.preferences.Settings;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.Locale;

/**
 * Stores, per account, the client certificate (mTLS) the user picked. The binding is keyed
 * by the account signature (server + email), so it is truly per-account.
 * <p>
 * Two sources are supported:
 * <ul>
 *   <li><b>KeyChain</b> — an alias of a credential installed in the Android system KeyChain.
 *       Only the alias is stored; the private key stays in the OS keystore.</li>
 *   <li><b>P12</b> — an imported {@code .p12}/{@code .pfx} file, copied into app-private
 *       storage. Its password is stored encrypted via {@link SecurePasswordManager}
 *       (Android-Keystore-backed).</li>
 * </ul>
 * The actual key material is resolved on demand by {@link ClientCertKeyManager}.
 * <p>
 * Bindings live in one of two <i>scopes</i>:
 * <ul>
 *   <li><b>account scope</b> — keyed by the account signature (server + email); set from
 *       {@code AccountDetailActivity} and used by a fully-formed account.</li>
 *   <li><b>host scope</b> — keyed by the server host alone, with no email. This is what the
 *       SSO login flow uses: at that point no account exists yet (the WebView and the
 *       pre-flight calls only know the server), and a client cert that gates the perimeter is
 *       a property of the host, not of any one user. {@link ClientCertKeyManager} falls back to
 *       the host binding when an account has none of its own, so the same cert keeps being
 *       presented once the SSO login resolves into a real account.</li>
 * </ul>
 */
public final class ClientCertManager {

    private static final String DEBUG_TAG = "ClientCertManager";
    private static final String TYPE_KEYCHAIN = "keychain";
    private static final String TYPE_P12 = "p12";
    private static final String P12_DIR = "client_certs";

    public enum Type {KEYCHAIN, P12}

    public enum ImportResult {SUCCESS, WRONG_PASSWORD, INVALID}

    /** A resolved description of an account's client cert. Never carries the p12 password. */
    public static final class ClientCertBinding {
        public Type type;
        public String alias;        // KEYCHAIN
        public String p12Path;      // P12
        public String displayName;  // for UI
        public String scopeId;      // the storage scope this was read from (account or host)
    }

    private static ClientCertManager instance;

    public static synchronized ClientCertManager instance() {
        if (instance == null) {
            instance = new ClientCertManager();
        }
        return instance;
    }

    private static SharedPreferences prefs() {
        return Settings.getCommonPreferences();
    }

    private static String key(String base, String scopeId) {
        return base + "_" + scopeId;
    }

    private static File p12File(String scopeId) {
        File dir = new File(SeadroidApplication.getAppContext().getFilesDir(), P12_DIR);
        return new File(dir, scopeId + ".p12");
    }

    /** Storage scope for a fully-formed account: keyed by its signature (server + email). */
    private static String accountScope(Account account) {
        return account.getEncryptSignature();
    }

    /**
     * Storage scope for a bare host (no email). Accepts either a full server URL
     * ({@code https://host:port/}) or an already-stripped {@code host:port}, and normalizes
     * both to the same key so a cert picked during SSO is found again by the resulting account.
     */
    private static String hostScope(String serverOrHost) {
        return "host_" + EncryptUtils.encryptMD5ToString(normalizeHost(serverOrHost));
    }

    private static String normalizeHost(String serverOrHost) {
        if (serverOrHost == null) {
            return "";
        }
        String s = serverOrHost.trim();
        int scheme = s.indexOf("://");
        if (scheme != -1) {
            s = s.substring(scheme + 3);
        }
        int slash = s.indexOf('/');
        if (slash != -1) {
            s = s.substring(0, slash);
        }
        return s.toLowerCase(Locale.ROOT);
    }

    // ---- read ----

    public ClientCertBinding getBinding(Account account) {
        return account == null ? null : getBindingForScope(accountScope(account));
    }

    /** Host-scoped binding, used by the SSO flow before any account exists. */
    public ClientCertBinding getBindingForHost(String serverOrHost) {
        if (TextUtils.isEmpty(serverOrHost)) {
            return null;
        }
        return getBindingForScope(hostScope(serverOrHost));
    }

    private ClientCertBinding getBindingForScope(String scopeId) {
        String type = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_TYPE, scopeId), null);

        // legacy bindings (pre-p12) stored only the bare alias with no type
        if (type == null) {
            String alias = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, scopeId), null);
            return TextUtils.isEmpty(alias) ? null : keychainBinding(alias, scopeId);
        }

        if (TYPE_KEYCHAIN.equals(type)) {
            String alias = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, scopeId), null);
            return TextUtils.isEmpty(alias) ? null : keychainBinding(alias, scopeId);
        }

        if (TYPE_P12.equals(type)) {
            String path = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PATH, scopeId), null);
            if (TextUtils.isEmpty(path) || !new File(path).exists()) {
                return null;
            }
            ClientCertBinding b = new ClientCertBinding();
            b.type = Type.P12;
            b.p12Path = path;
            b.displayName = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_NAME, scopeId), "client.p12");
            b.scopeId = scopeId;
            return b;
        }

        return null;
    }

    private ClientCertBinding keychainBinding(String alias, String scopeId) {
        ClientCertBinding b = new ClientCertBinding();
        b.type = Type.KEYCHAIN;
        b.alias = alias;
        b.displayName = alias;
        b.scopeId = scopeId;
        return b;
    }

    public String getDisplayName(Account account) {
        ClientCertBinding b = getBinding(account);
        return b == null ? null : b.displayName;
    }

    public String getDisplayNameForHost(String serverOrHost) {
        ClientCertBinding b = getBindingForHost(serverOrHost);
        return b == null ? null : b.displayName;
    }

    public boolean hasClientCert(Account account) {
        return getBinding(account) != null;
    }

    /** Decrypts and returns the imported p12 password; "" if none. Resolved lazily, not in getBinding(). */
    public String getP12Password(Account account) {
        return account == null ? "" : getP12PasswordForScope(accountScope(account));
    }

    /** Decrypts the imported p12 password for a binding's own scope (account or host). */
    public String getP12PasswordForScope(String scopeId) {
        if (TextUtils.isEmpty(scopeId)) {
            return "";
        }
        String enc = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PWD, scopeId), null);
        String iv = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_IV, scopeId), null);
        if (TextUtils.isEmpty(enc) || TextUtils.isEmpty(iv)) {
            return "";
        }
        String pwd = SecurePasswordManager.decryptPassword(enc, iv);
        return pwd == null ? "" : pwd;
    }

    // ---- write ----

    public void saveKeyChainAlias(Account account, String alias) {
        if (account == null) {
            return;
        }
        if (TextUtils.isEmpty(alias)) {
            deleteBinding(account);
            return;
        }
        saveKeyChainAliasForScope(accountScope(account), alias);
        SSLTrustManager.instance().invalidate(account);
    }

    /** Host-scoped variant for the SSO flow; no account to invalidate. */
    public void saveKeyChainAliasForHost(String serverOrHost, String alias) {
        if (TextUtils.isEmpty(serverOrHost)) {
            return;
        }
        if (TextUtils.isEmpty(alias)) {
            deleteBindingForHost(serverOrHost);
            return;
        }
        saveKeyChainAliasForScope(hostScope(serverOrHost), alias);
    }

    private void saveKeyChainAliasForScope(String scopeId, String alias) {
        deleteP12File(scopeId);
        prefs().edit()
                .putString(key(DataStoreKeys.KEY_CLIENT_CERT_TYPE, scopeId), TYPE_KEYCHAIN)
                .putString(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, scopeId), alias)
                .putString(key(DataStoreKeys.KEY_CLIENT_CERT_NAME, scopeId), alias)
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PATH, scopeId))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PWD, scopeId))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_IV, scopeId))
                .apply();
    }

    /**
     * Validate a .p12/.pfx without storing it (used to give the user immediate feedback on a
     * wrong password). Returns SUCCESS only if it opens and contains at least one key entry.
     */
    public ImportResult validateP12(byte[] data, String password) {
        if (data == null || data.length == 0) {
            return ImportResult.INVALID;
        }
        char[] pc = password == null ? new char[0] : password.toCharArray();
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(data), pc);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                if (ks.isKeyEntry(aliases.nextElement())) {
                    return ImportResult.SUCCESS;
                }
            }
            return ImportResult.INVALID; // parsed, but no private-key entry
        } catch (java.io.IOException e) {
            // PKCS12 surfaces a wrong password as an IOException (bad MAC / decrypt failure)
            return ImportResult.WRONG_PASSWORD;
        } catch (Exception e) {
            SafeLogs.e(DEBUG_TAG + ": p12 validate failed, " + e.getMessage());
            return ImportResult.INVALID;
        }
    }

    /** Validate, copy the .p12 into app storage, and store the (encrypted) password. */
    public ImportResult importP12(Account account, byte[] data, String password, String displayName) {
        if (account == null) {
            return ImportResult.INVALID;
        }
        ImportResult r = importP12ForScope(accountScope(account), data, password, displayName);
        if (r == ImportResult.SUCCESS) {
            SSLTrustManager.instance().invalidate(account);
        }
        return r;
    }

    /** Host-scoped variant for the SSO flow; no account to invalidate. */
    public ImportResult importP12ForHost(String serverOrHost, byte[] data, String password, String displayName) {
        if (TextUtils.isEmpty(serverOrHost)) {
            return ImportResult.INVALID;
        }
        return importP12ForScope(hostScope(serverOrHost), data, password, displayName);
    }

    private ImportResult importP12ForScope(String scopeId, byte[] data, String password, String displayName) {
        ImportResult r = validateP12(data, password);
        if (r != ImportResult.SUCCESS) {
            return r;
        }

        try {
            File out = p12File(scopeId);
            File dir = out.getParentFile();
            if (dir != null && !dir.exists() && !dir.mkdirs()) {
                SafeLogs.e(DEBUG_TAG + ": could not create client cert dir");
                return ImportResult.INVALID;
            }
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(data);
            }

            String pwdEnc = null, ivEnc = null;
            Pair<String, String> enc = SecurePasswordManager.encryptPassword(password == null ? "" : password);
            if (enc != null) {
                pwdEnc = enc.first;
                ivEnc = enc.second;
            }

            prefs().edit()
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_TYPE, scopeId), TYPE_P12)
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PATH, scopeId), out.getAbsolutePath())
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_NAME, scopeId),
                            TextUtils.isEmpty(displayName) ? out.getName() : displayName)
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PWD, scopeId), pwdEnc)
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_IV, scopeId), ivEnc)
                    .remove(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, scopeId))
                    .apply();

            return ImportResult.SUCCESS;
        } catch (Exception e) {
            SafeLogs.e(DEBUG_TAG + ": p12 import failed, " + e.getMessage());
            return ImportResult.INVALID;
        }
    }

    public void deleteBinding(Account account) {
        if (account == null) {
            return;
        }
        deleteBindingForScope(accountScope(account));
        SSLTrustManager.instance().invalidate(account);
    }

    public void deleteBindingForHost(String serverOrHost) {
        if (TextUtils.isEmpty(serverOrHost)) {
            return;
        }
        deleteBindingForScope(hostScope(serverOrHost));
    }

    private void deleteBindingForScope(String scopeId) {
        deleteP12File(scopeId);
        prefs().edit()
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_TYPE, scopeId))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, scopeId))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PATH, scopeId))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PWD, scopeId))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_IV, scopeId))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_NAME, scopeId))
                .apply();
    }

    private void deleteP12File(String scopeId) {
        File f = p12File(scopeId);
        if (f.exists() && !f.delete()) {
            SafeLogs.e(DEBUG_TAG + ": could not delete old p12 " + f.getAbsolutePath());
        }
    }
}
