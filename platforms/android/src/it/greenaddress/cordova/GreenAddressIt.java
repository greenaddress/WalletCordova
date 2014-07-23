/*
       Licensed to the Apache Software Foundation (ASF) under one
       or more contributor license agreements.  See the NOTICE file
       distributed with this work for additional information
       regarding copyright ownership.  The ASF licenses this file
       to you under the Apache License, Version 2.0 (the
       "License"); you may not use this file except in compliance
       with the License.  You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

       Unless required by applicable law or agreed to in writing,
       software distributed under the License is distributed on an
       "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
       KIND, either express or implied.  See the License for the
       specific language governing permissions and limitations
       under the License.
 */

package it.greenaddress.cordova;

import android.os.Bundle;
import org.apache.cordova.*;
import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import java.util.logging.Logger;
import android.os.Parcelable;
import android.net.Uri;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.os.Build;
import android.content.pm.ApplicationInfo;
import android.util.Base64;

class CustomNativeAccess {
    @JavascriptInterface
    public String clearCookies() {
        CookieManager.getInstance().removeAllCookie();
        return "ok";
    }
}

public class GreenAddressIt extends CordovaActivity 
{
    private Intent lastIntent = null;

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        // in previous versions there was a flaw which caused qr scanning history to be stored by
        // our zxing plugin because Intents.Scan.SAVE_HISTORY was not set to false - the history
        // from previous versions is removed here:
        getApplicationContext().deleteDatabase("barcode_scanner_history.db");

        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction()) && getIntent().getBooleanExtra("continue", true)) {
            // ignore nfc, to avoid having nfc service and app not reparenting (disappears from history) and send intent just to start app normally
            final Intent intent = getIntent();//.cloneFilter();//new Intent(getApplicationContext(), GreenAddressIt.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            intent.putExtra("continue", false);
            startActivity(intent);
            finish();
            return;
        }
        if (getIntent().hasCategory(Intent.CATEGORY_BROWSABLE)) {
            // ignore opening uri to deparent from browser
            final Intent intent = new Intent(Intent.ACTION_VIEW, getIntent().getData(), getApplicationContext(), GreenAddressIt.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(intent);
            finish();
            return;
        }

        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            if ( 0 != ( getApplicationInfo().flags &= ApplicationInfo.FLAG_DEBUGGABLE ) ) {
                WebView.setWebContentsDebuggingEnabled(true);
            }
        }
        if (!isTaskRoot()) {
            // https://code.google.com/p/android/issues/detail?id=2373
            final Intent intent = getIntent();
            final String action = intent.getAction();
            if (intent.hasCategory(Intent.CATEGORY_LAUNCHER) && action != null && action.equals(Intent.ACTION_MAIN)) {
                finish();
                return;
            }
        }
        super.init();
        // Set by <content src="index.html" /> in config.xml
        super.appView.getSettings().setUserAgentString("GAITCordova;" + super.appView.getSettings().getUserAgentString());
        super.appView.addJavascriptInterface(new CustomNativeAccess(), "CustomNativeAccess");
        if (Intent.ACTION_VIEW.equals(getIntent().getAction())) {
            processView(getIntent());
        } else {
            super.clearCache();
            super.setIntegerProperty("splashscreen", R.drawable.splash);
            final Intent intent = getIntent();
            if (intent != null) {
                final String hash = intent.getStringExtra("hash");
                if (hash != null) {
                    super.loadUrl(getBaseURL() + "#/?redir=" + Uri.encode(hash + "?&filtered_intent=1"));
                    return;
                }
            }
            super.loadUrl(getBaseURL());
        }
    }

    protected String getBaseURL() {
        final SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences(this.getActivity());
        String language;
        if (sharedPrefs.contains("language")) {
            language = (String)sharedPrefs.getAll().get("language");
        } else {
            language = "en";
        }
        return "file:///android_asset/www/greenaddress.it/" + language + "/wallet.html";
    }

    private void processView(final Intent intent) {
        if (intent == null) {
            return;
        }
        if (intent.getData() == null) {
            return;
        }
        if ("bitcoin".equals(intent.getData().getScheme())) {
            String uri = "/uri/?uri=" + Uri.encode(intent.getData().toString());
            super.loadUrl(getBaseURL() + "#" + uri);
        } else if (intent.getData().getPath() == null) {
            super.loadUrl(getBaseURL());
        } else {
            String path = intent.getData().getPath();
            if (path.length() > 4 && path.charAt(0) == '/' && path.charAt(3) == '/') {
                // hackish language URL detection
                path = path.substring(3);
            }
            String url = getBaseURL() + "#" + path,
                   query = intent.getData().getQuery(),
                   fragment = intent.getData().getFragment();
            if (path.startsWith("/wallet/")) {
                if (fragment != null && !fragment.isEmpty()) {
                    url = getBaseURL() + '#' + fragment;
                } else {
                    url = getBaseURL();
                }
                super.loadUrl(url);
            } else if (path.startsWith("/pay/") || path.startsWith("/redeem/") || path.startsWith("/uri/")) {
                if (query != null && !query.isEmpty()) {
                    url += "?" + query;
                }
                super.loadUrl(url);
            } else {  // not a wallet url - shouldn't happen given the filters work correctly
            }
        }
    }
    
    private void handleWidget(final Intent intent) {
        if (intent != null) {
            final String hash = intent.getStringExtra("hash");
            if (hash != null) {
                if (("/send".equals(hash) || "/receive".equals(hash))) {
                        final String js = "location.hash=\"#" +hash+"\"";
                        super.sendJavascript(js);
                }
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (Intent.ACTION_VIEW.equals(getIntent().getAction())) {    
            processView(getIntent());
        }
        handleWidget(lastIntent);
        if (lastIntent != null && Intent.ACTION_VIEW.equals(lastIntent.getAction())) {
            processView(lastIntent);
        }
        lastIntent = null;

    }

    @Override
    protected void onNewIntent(Intent intent) {
        lastIntent = intent;
        processView(intent);
        super.onNewIntent(intent);
        setIntent(intent);
    }
    
}
