package com.seafile.seadroid2.ui.account.sso;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.security.KeyChain;
import android.text.Editable;
import android.text.TextUtils;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.NavUtils;
import androidx.core.app.TaskStackBuilder;
import androidx.lifecycle.Observer;

import com.blankj.utilcode.util.CollectionUtils;
import com.blankj.utilcode.util.NetworkUtils;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputLayout;
import com.seafile.seadroid2.R;
import com.seafile.seadroid2.account.Account;
import com.seafile.seadroid2.config.Constants;
import com.seafile.seadroid2.databinding.SingleSignOnWelcomeLayoutBinding;
import com.seafile.seadroid2.framework.model.server.ServerInfoModel;
import com.seafile.seadroid2.framework.util.ContentResolvers;
import com.seafile.seadroid2.framework.util.SLogs;
import com.seafile.seadroid2.framework.util.StringUtils;
import com.seafile.seadroid2.framework.util.Toasts;
import com.seafile.seadroid2.ssl.ClientCertManager;
import com.seafile.seadroid2.ui.WidgetUtils;
import com.seafile.seadroid2.ui.account.AccountsActivity;
import com.seafile.seadroid2.ui.account.SeafileAuthenticatorActivity;
import com.seafile.seadroid2.ui.base.BaseActivityWithVM;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Single Sign-On welcome page
 * <p/>
 */
public class SingleSignOnActivity extends BaseActivityWithVM<SingleSignOnViewModel> implements Toolbar.OnMenuItemClickListener {
    public static final String DEBUG_TAG = "SingleSignOnActivity";

    public static final String SINGLE_SIGN_ON_HTTPS_PREFIX = "https://";

    private SingleSignOnWelcomeLayoutBinding binding;

    private ActivityResultLauncher<Intent> authLauncher;
    private ActivityResultLauncher<String[]> p12PickerLauncher;

    /**
     * The client certificate (mTLS) chosen on this screen, if any. Held until {@link #doNext()}
     * persists it host-scoped, so the cert is in place before the first request to the server's
     * mTLS-gated perimeter. {@code null} means "no change".
     */
    private PendingCert pendingCert;

    /** A not-yet-persisted client cert choice (KeyChain alias, imported .p12, or removal). */
    private static class PendingCert {
        boolean cleared;                  // user tapped "Remove"
        ClientCertManager.Type type;      // otherwise KEYCHAIN or P12
        String alias;                     // KEYCHAIN
        byte[] p12Data;                   // P12 (already validated against p12Password)
        String p12Password;               // P12
        String displayName;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = SingleSignOnWelcomeLayoutBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        registerAuthLauncher();
        p12PickerLauncher = registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
            if (uri != null) {
                onP12Picked(uri);
            }
        });

        initView();
        initViewModel();

        getOnBackPressedDispatcher().addCallback(new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (timer != null) {
                    stopAction();
                    if (isDialogShowing()) {
                        dismissLoadingDialog();
                    }
                } else {
                    finish();
                }
            }
        });
    }

    private void registerAuthLauncher() {
        authLauncher = registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), new ActivityResultCallback<ActivityResult>() {
            @Override
            public void onActivityResult(ActivityResult o) {
                setResult(o.getResultCode(), o.getData());
                finish();
            }
        });
    }

    private void initView() {
        String url = getIntent().getStringExtra(SeafileAuthenticatorActivity.SINGLE_SIGN_ON_SERVER_URL);
        if (!TextUtils.isEmpty(url)) {
            binding.serverEditText.setText(url);
            int len = url.length();
            binding.serverEditText.setSelection(len, len);
        } else {
            binding.serverEditText.setText(SINGLE_SIGN_ON_HTTPS_PREFIX);
            int prefixLen = SINGLE_SIGN_ON_HTTPS_PREFIX.length();
            binding.serverEditText.setSelection(prefixLen, prefixLen);
        }

        binding.nextBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                doNext();
            }
        });

        binding.clientCertButton.setOnClickListener(v -> showCertSourceChooser());
        binding.clientCertClear.setOnClickListener(v -> {
            PendingCert p = new PendingCert();
            p.cleared = true;
            pendingCert = p;
            updateClientCertStatus();
        });
        updateClientCertStatus();

        applyEdgeToEdge(binding.getRoot());
        Toolbar toolbar = getActionBarToolbar();
        toolbar.setOnMenuItemClickListener(this);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle(R.string.shib_login_title);
        }
    }

    @Override
    public boolean onMenuItemClick(MenuItem item) {
        return false;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                finish();
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void initViewModel() {
        getViewModel().getRefreshLiveData().observe(this, new Observer<Boolean>() {
            @Override
            public void onChanged(Boolean aBoolean) {
                showLoadingDialog(aBoolean);
            }
        });

        getViewModel().getServerInfoLiveData().observe(this, new Observer<ServerInfoModel>() {
            @Override
            public void onChanged(ServerInfoModel serverInfoModel) {
                String host = getServerHost();
                if (CollectionUtils.isEmpty(serverInfoModel.features)) {
                    dismissLoadingDialog();
                    openAuthorizePage(host);
                    return;
                }

                if (!serverInfoModel.features.contains("client-sso-via-local-browser")) {
                    dismissLoadingDialog();
                    openAuthorizePage(host);
                    return;
                }

                getViewModel().getSsoLink(host);

            }
        });

        getViewModel().getSsoLinkLiveData().observe(this, new Observer<String>() {
            @Override
            public void onChanged(String s) {
                openLocalBrowser(s);
            }
        });

        getViewModel().getSsoStatusLiveData().observe(this, new Observer<String>() {
            @Override
            public void onChanged(String s) {
                SLogs.e(s);
                startDelayedAction();
            }
        });

        getViewModel().getAccountLiveData().observe(this, new Observer<Account>() {
            @Override
            public void onChanged(Account account) {
                onLoggedIn(account);
            }
        });
    }

    private void doNext() {
        String host = getServerHost();
        if (isServerHostValid(host)) {
            // bind (or clear) the chosen client cert against this host before the first request,
            // so the mTLS handshake to the perimeter (pre-flight + WebView) already presents it
            persistPendingCert(host);
            getViewModel().loadServerInfo(host);
        }
    }

    /** Lets the user choose where the client certificate comes from: KeyChain or a .p12 file. */
    private void showCertSourceChooser() {
        CharSequence[] items = {
                getString(R.string.client_cert_source_keychain),
                getString(R.string.client_cert_source_p12)
        };
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.client_cert_choose)
                .setItems(items, (dialog, which) -> {
                    if (which == 0) {
                        chooseFromKeyChain();
                    } else {
                        p12PickerLauncher.launch(new String[]{
                                "application/x-pkcs12", "application/pkcs12",
                                "application/octet-stream", "*/*"});
                    }
                })
                .show();
    }

    /**
     * Opens the Android system credential picker (KeyChain). The private key stays in the OS
     * keystore; we only remember the chosen alias.
     */
    private void chooseFromKeyChain() {
        String host = null;
        int port = -1;
        String serverURL = getServerHost();
        try {
            if (!TextUtils.isEmpty(serverURL)) {
                URI uri = new URI(serverURL.trim());
                host = uri.getHost();
                port = uri.getPort();
            }
        } catch (URISyntaxException ignored) {
        }

        KeyChain.choosePrivateKeyAlias(this, alias -> runOnUiThread(() -> {
            // alias is null when the user cancels; keep the previous selection in that case
            if (alias != null) {
                PendingCert p = new PendingCert();
                p.type = ClientCertManager.Type.KEYCHAIN;
                p.alias = alias;
                p.displayName = alias;
                pendingCert = p;
                updateClientCertStatus();
            }
        }), new String[]{"RSA", "EC"}, null, host, port, null);
    }

    private void onP12Picked(Uri uri) {
        byte[] data = ContentResolvers.getFileContentFromUri(getContentResolver(), uri);
        if (data == null || data.length == 0) {
            Toasts.show(R.string.client_cert_import_failed);
            return;
        }
        String name = ContentResolvers.getFileNameFromUri(getContentResolver(), uri);
        if (TextUtils.isEmpty(name)) {
            name = "client.p12";
        }
        promptP12Password(data, name);
    }

    /** Asks for the .p12 password and validates it before accepting the import. */
    private void promptP12Password(byte[] data, String displayName) {
        View view = getLayoutInflater().inflate(R.layout.dialog_p12_password, null);
        TextInputLayout layout = view.findViewById(R.id.p12_password_layout);
        EditText input = view.findViewById(R.id.p12_password_input);

        AlertDialog dialog = new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.client_cert_p12_password_title)
                .setMessage(displayName)
                .setView(view)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.ok, null) // overridden below so a wrong password keeps the dialog open
                .create();

        dialog.setOnShowListener(d -> {
            Button positive = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            positive.setOnClickListener(v -> {
                String pwd = input.getText().toString();
                ClientCertManager.ImportResult r = ClientCertManager.instance().validateP12(data, pwd);
                if (r == ClientCertManager.ImportResult.SUCCESS) {
                    PendingCert p = new PendingCert();
                    p.type = ClientCertManager.Type.P12;
                    p.p12Data = data;
                    p.p12Password = pwd;
                    p.displayName = displayName;
                    pendingCert = p;
                    updateClientCertStatus();
                    dialog.dismiss();
                } else if (r == ClientCertManager.ImportResult.WRONG_PASSWORD) {
                    layout.setError(getString(R.string.client_cert_p12_wrong_password));
                } else {
                    layout.setError(getString(R.string.client_cert_import_failed));
                }
            });
        });
        dialog.show();
    }

    private void updateClientCertStatus() {
        String label = null;

        if (pendingCert != null) {
            if (!pendingCert.cleared) {
                label = pendingCert.displayName;
            }
        } else {
            // no change this session: reflect what is already stored for this host
            label = ClientCertManager.instance().getDisplayNameForHost(getServerHost());
        }

        if (TextUtils.isEmpty(label)) {
            binding.clientCertStatus.setText(R.string.client_cert_none);
            binding.clientCertClear.setVisibility(View.GONE);
        } else {
            binding.clientCertStatus.setText(getString(R.string.client_cert_selected, label));
            binding.clientCertClear.setVisibility(View.VISIBLE);
        }
    }

    private void persistPendingCert(String host) {
        if (pendingCert == null) {
            return;
        }
        ClientCertManager mgr = ClientCertManager.instance();
        if (pendingCert.cleared) {
            mgr.deleteBindingForHost(host);
        } else if (pendingCert.type == ClientCertManager.Type.KEYCHAIN) {
            mgr.saveKeyChainAliasForHost(host, pendingCert.alias);
        } else if (pendingCert.type == ClientCertManager.Type.P12) {
            mgr.importP12ForHost(host, pendingCert.p12Data, pendingCert.p12Password, pendingCert.displayName);
        }
        // persisted; subsequent re-entry should reflect the stored binding again
        pendingCert = null;
    }

    private boolean isServerHostValid(String hostUrl) {
        if (TextUtils.isEmpty(hostUrl)) {
            Toasts.show(R.string.shib_server_url_empty);
            return false;
        }

        if (!hostUrl.startsWith(SINGLE_SIGN_ON_HTTPS_PREFIX)) {
            Toasts.show(getString(R.string.shib_server_incorrect_prefix));
            return false;
        }

        String serverUrl1 = hostUrl
                .toLowerCase(Locale.ROOT)
                .replace("https://", "")
                .replace("http://", "");
        if (TextUtils.isEmpty(serverUrl1)) {
            Toasts.show(R.string.err_server_andress_empty);
            return false;
        }

        return true;
    }

    private String getServerHost() {
        Editable editable = binding.serverEditText.getText();
        if (null == editable) {
            return null;
        }

        String host = editable.toString().trim();
        if (!host.endsWith("/")) {
            host = host + "/";
        }
        return host;
    }

    private void openAuthorizePage(String serverUrl) {
        if (!NetworkUtils.isConnected()) {
            Toasts.show(R.string.network_down);
            return;
        }

        Intent intent = new Intent(this, SingleSignOnAuthorizeActivity.class);
        intent.putExtra(SeafileAuthenticatorActivity.SINGLE_SIGN_ON_SERVER_URL, serverUrl);
        intent.putExtras(getIntent());
        authLauncher.launch(intent);
    }


    private String ssoLink = null;

    private void openLocalBrowser(String url) {
        ssoLink = url;
        WidgetUtils.openUrlByLocalBrowser(this, ssoLink);
    }

    @Override
    protected void onRestart() {
        super.onRestart();
        getSsoStatus();
    }

    @Override
    protected void onStop() {
        super.onStop();
        getViewModel().getRefreshLiveData().setValue(false);
        stopAction();
    }

    private void getSsoStatus() {
        if (TextUtils.isEmpty(ssoLink)) {
            return;
        }

        // https://host/client-sso/13de82ce0861430ba5a9f672cf89fe41fbaa6c7c94487b92ff8c8d76c260/
        String link = StringUtils.trimEnd(ssoLink, "/");
        String token = link.substring(link.lastIndexOf("/") + 1);
        String host = getServerHost();
        getViewModel().getSsoStatus(host, token);
    }

    private void onLoggedIn(Account account) {
        Intent retData = new Intent();
//        retData.putExtras(getIntent());
        retData.putExtra(android.accounts.AccountManager.KEY_ACCOUNT_NAME, account.getSignature());
        retData.putExtra(android.accounts.AccountManager.KEY_AUTHTOKEN, account.getToken());
        retData.putExtra(android.accounts.AccountManager.KEY_ACCOUNT_TYPE, getIntent().getStringExtra(SeafileAuthenticatorActivity.ARG_ACCOUNT_TYPE));


        retData.putExtra(SeafileAuthenticatorActivity.ARG_EMAIL, account.getEmail());
        retData.putExtra(SeafileAuthenticatorActivity.ARG_CONTACT_EMAIL, account.getContactEmail());
        retData.putExtra(SeafileAuthenticatorActivity.ARG_NAME, account.getName());
        retData.putExtra(SeafileAuthenticatorActivity.ARG_SHIB, account.is_shib);
        retData.putExtra(SeafileAuthenticatorActivity.ARG_SERVER_URI, account.getServer());

        retData.putExtra(SeafileAuthenticatorActivity.ARG_AVATAR_URL, account.getAvatarUrl());
        retData.putExtra(SeafileAuthenticatorActivity.ARG_SPACE_TOTAL, account.getTotalSpace());
        retData.putExtra(SeafileAuthenticatorActivity.ARG_SPACE_USAGE, account.getUsageSpace());
        retData.putExtra(SeafileAuthenticatorActivity.ARG_SHIB, true);

        setResult(RESULT_OK, retData);
        finish();
    }


    private Timer timer;

    public void startDelayedAction() {
        if (timer != null) {
            timer.cancel();
        }

        timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                runOnUiThread(new TimerTask() {
                    @Override
                    public void run() {
                        getSsoStatus();
                    }
                });
            }
        }, 2 * 1000);
    }

    public void stopAction() {
        if (timer != null) {
            timer.cancel();
            timer = null;
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopAction();
    }
}
