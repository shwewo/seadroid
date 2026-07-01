package com.seafile.seadroid2.view.webview;

import static com.blankj.utilcode.util.ActivityUtils.startActivity;

import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.webkit.ClientCertRequest;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import com.github.lzyzsd.jsbridge.BridgeWebView;
import com.github.lzyzsd.jsbridge.BridgeWebViewClient;
import com.seafile.seadroid2.account.Account;
import com.seafile.seadroid2.account.SupportAccountManager;
import com.seafile.seadroid2.framework.util.SLogs;
import com.seafile.seadroid2.framework.util.Token2SessionConverts;
import com.seafile.seadroid2.ssl.ClientCertKeyManager;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import java.util.HashMap;
import java.util.Map;

public class SeaWebViewClient extends BridgeWebViewClient {

    private OnWebPageListener onWebPageListener;

    public void setOnWebPageListener(OnWebPageListener onWebPageListener) {
        this.onWebPageListener = onWebPageListener;
    }

    public SeaWebViewClient(BridgeWebView webView) {
        super(webView);
    }

    @Override
    public void onPageStarted(WebView view, String url, Bitmap favicon) {
        super.onPageStarted(view, url, favicon);
        if (onWebPageListener != null) {
            onWebPageListener.onPageStarted(view, url, favicon);
        }
    }

    @Override
    public void onPageFinished(WebView view, String url) {
        super.onPageFinished(view, url);
        if (onWebPageListener != null) {
            onWebPageListener.onPageFinished(view, url);
        }
    }

    @Override
    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
        super.onReceivedError(view, request, error);
        if (onWebPageListener != null) {
            onWebPageListener.onReceivedError(view, request, error);
        }
    }

    @Override
    public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
        super.onReceivedHttpError(view, request, errorResponse);
        if (onWebPageListener != null) {
            onWebPageListener.onReceivedHttpError(view, request, errorResponse);
        }
    }

    @Override
    public void onReceivedClientCertRequest(WebView view, ClientCertRequest request) {
        // KeyChain / keystore access blocks and must not run on the UI thread.
        // request.proceed() / request.ignore() are safe to call from any thread.
        new Thread(() -> {
            try {
                Account account = SupportAccountManager.getInstance().getCurrentAccount();
                ClientCertKeyManager km = new ClientCertKeyManager(
                        view.getContext().getApplicationContext(), () -> account);
                String alias = km.chooseClientAlias(new String[]{"RSA", "EC"}, request.getPrincipals(), null);
                if (alias == null) {
                    request.ignore();
                    return;
                }
                PrivateKey key = km.getPrivateKey(alias);
                X509Certificate[] chain = km.getCertificateChain(alias);
                if (key != null && chain != null && chain.length > 0) {
                    request.proceed(key, chain);
                } else {
                    request.ignore();
                }
            } catch (Exception e) {
                SLogs.e("SeaWebViewClient: onReceivedClientCertRequest failed: " + e.getMessage());
                request.ignore();
            }
        }, "webview-client-cert").start();
    }

    @Override
    public boolean shouldOverrideUrlLoading(WebView wb, WebResourceRequest request) {
        String url = request.getUrl().toString();

        //Open the System app
        if (url.startsWith("tel:") ||
                url.startsWith("sms:") ||
                url.startsWith("smsto:") ||
                url.startsWith("mailto:") ||
                url.startsWith("mms:") ||
                url.startsWith("mmsto:")) {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);
            return true;
        }

//        if (url.startsWith(SeaWebView.URL_LOGIN)) {
//            reloadUrl(url, wb);
//            return true;
//        }

        return super.shouldOverrideUrlLoading(wb, request);
    }


//    private void reloadUrl(String url, WebView wb) {
//        CookieManager manager = CookieManager.getInstance();
//        if (manager == null) {
//            go(url, wb);
//            return;
//        }
//
//        String q = URLs.getQuery(url);
//        if (!TextUtils.isEmpty(q) && q.startsWith("next=")) {
//            q = q.substring(5);
//        }
//
//        String server = SupportAccountManager.getInstance().getCurrentAccount().getProtocolHost();
//        String newUrl = server + q;
//
//        manager.removeAllCookies(value -> goWithToken(newUrl, wb, true));
//    }

    private String mOriginTargetUrl;

    public void go(String targetUrl, WebView wb) {
        loadWithToken(targetUrl, wb, true);
    }

    public void loadWithoutToken(String targetUrl, WebView wb) {
        loadWithToken(targetUrl, wb, false);
    }

    public void loadWithToken(String targetUrl, WebView wb, boolean isRedirect) {
        mOriginTargetUrl = targetUrl;

        if (isRedirect) {
            Map<String, String> map = new HashMap<>();

            Account account = SupportAccountManager.getInstance().getCurrentAccount();
            if (account != null) {
                map.put("Authorization", "Token " + account.token);
            }

            String rUrl = buildUrl(mOriginTargetUrl);
            wb.loadUrl(rUrl, map);
        } else {
            wb.loadUrl(mOriginTargetUrl);
            SLogs.d("targetUrl: " + mOriginTargetUrl);
        }
    }

    private String buildUrl(String url) {
        if (!url.startsWith("http")) {
            return url;
        }

        return Token2SessionConverts.buildUrl(url);
    }

}

