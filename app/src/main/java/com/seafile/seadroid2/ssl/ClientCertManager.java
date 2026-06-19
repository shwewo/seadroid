package com.seafile.seadroid2.ssl;

import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Pair;

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

    private static String key(String base, Account account) {
        return base + "_" + account.getEncryptSignature();
    }

    private static File p12File(Account account) {
        File dir = new File(SeadroidApplication.getAppContext().getFilesDir(), P12_DIR);
        return new File(dir, account.getEncryptSignature() + ".p12");
    }

    // ---- read ----

    public ClientCertBinding getBinding(Account account) {
        if (account == null) {
            return null;
        }

        String type = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_TYPE, account), null);

        // legacy bindings (pre-p12) stored only the bare alias with no type
        if (type == null) {
            String alias = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, account), null);
            return TextUtils.isEmpty(alias) ? null : keychainBinding(alias);
        }

        if (TYPE_KEYCHAIN.equals(type)) {
            String alias = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, account), null);
            return TextUtils.isEmpty(alias) ? null : keychainBinding(alias);
        }

        if (TYPE_P12.equals(type)) {
            String path = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PATH, account), null);
            if (TextUtils.isEmpty(path) || !new File(path).exists()) {
                return null;
            }
            ClientCertBinding b = new ClientCertBinding();
            b.type = Type.P12;
            b.p12Path = path;
            b.displayName = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_NAME, account), "client.p12");
            return b;
        }

        return null;
    }

    private ClientCertBinding keychainBinding(String alias) {
        ClientCertBinding b = new ClientCertBinding();
        b.type = Type.KEYCHAIN;
        b.alias = alias;
        b.displayName = alias;
        return b;
    }

    public String getDisplayName(Account account) {
        ClientCertBinding b = getBinding(account);
        return b == null ? null : b.displayName;
    }

    public boolean hasClientCert(Account account) {
        return getBinding(account) != null;
    }

    /** Decrypts and returns the imported p12 password; "" if none. Resolved lazily, not in getBinding(). */
    public String getP12Password(Account account) {
        if (account == null) {
            return "";
        }
        String enc = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PWD, account), null);
        String iv = prefs().getString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_IV, account), null);
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

        deleteP12File(account);
        prefs().edit()
                .putString(key(DataStoreKeys.KEY_CLIENT_CERT_TYPE, account), TYPE_KEYCHAIN)
                .putString(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, account), alias)
                .putString(key(DataStoreKeys.KEY_CLIENT_CERT_NAME, account), alias)
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PATH, account))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PWD, account))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_IV, account))
                .apply();

        SSLTrustManager.instance().invalidate(account);
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

        ImportResult r = validateP12(data, password);
        if (r != ImportResult.SUCCESS) {
            return r;
        }

        try {
            File out = p12File(account);
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
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_TYPE, account), TYPE_P12)
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PATH, account), out.getAbsolutePath())
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_NAME, account),
                            TextUtils.isEmpty(displayName) ? out.getName() : displayName)
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PWD, account), pwdEnc)
                    .putString(key(DataStoreKeys.KEY_CLIENT_CERT_P12_IV, account), ivEnc)
                    .remove(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, account))
                    .apply();

            SSLTrustManager.instance().invalidate(account);
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

        deleteP12File(account);
        prefs().edit()
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_TYPE, account))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_ALIAS, account))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PATH, account))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_PWD, account))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_P12_IV, account))
                .remove(key(DataStoreKeys.KEY_CLIENT_CERT_NAME, account))
                .apply();

        SSLTrustManager.instance().invalidate(account);
    }

    private void deleteP12File(Account account) {
        File f = p12File(account);
        if (f.exists() && !f.delete()) {
            SafeLogs.e(DEBUG_TAG + ": could not delete old p12 " + f.getAbsolutePath());
        }
    }
}
