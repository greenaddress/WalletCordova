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
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import java.util.logging.Logger;
import android.os.Parcelable;
import android.net.Uri;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;

class CustomNativeAccess {
    @JavascriptInterface
    public String clearCookies() {
        CookieManager.getInstance().removeAllCookie();
        return "ok";
    }
}

public class GreenAddressIt extends CordovaActivity 
{
    private boolean shown;

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        if (!isTaskRoot()) {
            // https://code.google.com/p/android/issues/detail?id=2373
            Intent intent = getIntent();
            String action = intent.getAction();
            if (intent.hasCategory(Intent.CATEGORY_LAUNCHER) && action != null && action.equals(Intent.ACTION_MAIN)) {
                finish();
                return;
            }
        }
        super.init();
        shown = false;
        // Set by <content src="index.html" /> in config.xml
        super.appView.getSettings().setUserAgentString("GAITCordova;" + super.appView.getSettings().getUserAgentString());
        super.appView.addJavascriptInterface(new CustomNativeAccess(), "CustomNativeAccess");
        if (Intent.ACTION_VIEW.equals(getIntent().getAction())) {
            processView(getIntent());
        } else {
            super.clearCache();
            super.setIntegerProperty("splashscreen", R.drawable.splash);
            super.loadUrl(getBaseURL());
        }
    }

    private void processNFC(final Intent intent) {
        final Parcelable[] rawMsgs = intent.getParcelableArrayExtra(
        NfcAdapter.EXTRA_NDEF_MESSAGES);
        final NdefMessage msg = (NdefMessage) rawMsgs[0];
        Logger.getLogger("CordovaLog").info("OnIntent" + msg.getRecords()[0].getPayload());
    }

    protected String getBaseURL() {
        SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences(this.getActivity());
        String language;
        if (sharedPrefs.contains("language")) {
            language = (String)sharedPrefs.getAll().get("language");
            Logger.getLogger("CordovaLog").info(language);
        } else {
            Logger.getLogger("CordovaLog").info("doesn't");
            language = "en";
        }
        return "file:///android_asset/www/greenaddress.it/" + language + "/wallet.html";
    }

    private void processView(final Intent intent) {
        if (getIntent().getData().getScheme().equals("bitcoin")) {
            String uri = "/uri/?uri=" + Uri.encode(getIntent().getData().toString());
            super.loadUrl(getBaseURL() + "#/?redir=" + Uri.encode(uri));
        } else if (getIntent().getData().getPath() == null) {
            super.loadUrl(getBaseURL());
        } else {
            // all of /redeem/, /pay/, /uri/ require login, so go to /?redir directly
            String path = getIntent().getData().getPath();
            if (path.length() > 4 && path.charAt(0) == '/' && path.charAt(3) == '/') {
                // hackish language URL detection
                path = path.substring(3);
            }
            String url = getBaseURL() + "#/?filtered_intent=1&redir=" + path,
                   query = getIntent().getData().getQuery(),
                   fragment = getIntent().getData().getFragment();
            if (path.startsWith("/wallet/")) {
                if (fragment != null && !fragment.isEmpty()) {
                    if (fragment.indexOf('?') != -1) fragment += "&filtered_intent=1";
                    else fragment += "?filtered_intent=1";
                    url = getBaseURL() + '#' + fragment;
                } else {
                    url = getBaseURL() + "#/?filtered_intent=1";
                }
                super.loadUrl(url);
            } else if (path.startsWith("/pay/") || path.startsWith("/redeem/") || path.startsWith("/uri/")) {
    	        if (query != null && !query.isEmpty()) {
    		        url += Uri.encode("?" + query);
                }
                super.loadUrl(url);
            } else {  // not a wallet url - shouldn't happen given the filters work correctly
                super.loadUrl(getBaseURL());
            }
        }
        shown = true;
    }

    @Override
    protected void onResume() {
        super.onResume();
        Logger.getLogger("CordovaLog").info("OnResume");
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            processNFC(getIntent());
        }
        if (Intent.ACTION_VIEW.equals(getIntent().getAction())) {
            if (!shown)  // don't reload the page on return to "parent" intent-calling app
                processView(getIntent());
        }
    }
}
