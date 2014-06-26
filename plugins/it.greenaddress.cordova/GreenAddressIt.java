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
import android.nfc.NfcAdapter;
import java.util.logging.Logger;
import android.os.Parcelable;
import android.net.Uri;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.os.Build;
import android.content.pm.ApplicationInfo;

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
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            // ignore nfc, to avoid having nfc service and app not reparenting (disappears from history) and send intent just to start app normally
            Logger.getLogger("CordovaLog").info(" NFC finishing");
            final Intent intent = new Intent(getApplicationContext(), GreenAddressIt.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            intent.putExtra(NfcAdapter.EXTRA_NDEF_MESSAGES, getIntent().getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES));
            startActivity(intent);
            finish();
            return;
        }
        if (getIntent().hasCategory(Intent.CATEGORY_BROWSABLE)) {
            // ignore nfc, to avoid having nfc service and app not reparenting (disappears from history) and send intent just to start app normally
            Logger.getLogger("CordovaLog").info(" browsable");
            final Intent intent = new Intent(Intent.ACTION_VIEW, getIntent().getData(), getApplicationContext(), GreenAddressIt.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_SINGLE_TOP);
            //intent.putExtras(getIntent());
            startActivity(intent);
            finish();
            return;
        }

        Logger.getLogger("CordovaLog").info("onCreate after super");
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            if ( 0 != ( getApplicationInfo().flags &= ApplicationInfo.FLAG_DEBUGGABLE ) ) {
                Logger.getLogger("CordovaLog").info("enabling debugging for webview");
                WebView.setWebContentsDebuggingEnabled(true);
            }
        }
        if (!isTaskRoot()) {
            Logger.getLogger("CordovaLog").info("!isTaskRoot");
            // https://code.google.com/p/android/issues/detail?id=2373
            final Intent intent = getIntent();
            final String action = intent.getAction();
            Logger.getLogger("CordovaLog").info("!isTaskRoot " + intent.toString());
            Logger.getLogger("CordovaLog").info("!isTaskRoot " + action);
            if (intent.hasCategory(Intent.CATEGORY_LAUNCHER) && action != null && action.equals(Intent.ACTION_MAIN)) {
                Logger.getLogger("CordovaLog").info("finishing");
                finish();
                return;
            }
        }
        Logger.getLogger("CordovaLog").info("onCreate after super" + getIntent().toString());
        if (getIntent()!= null && getIntent().getExtras() != null)  {
            for (String key : getIntent().getExtras().keySet()) {
                    Object value = getIntent().getExtras().get(key);
                    Logger.getLogger("CordovaLog").info(String.format("onResume %s %s (%s)", key, value.toString(), value.getClass().getName()));
            }
        }
        Logger.getLogger("CordovaLog").info("about to call init");
        super.init();
        Logger.getLogger("CordovaLog").info("init called");
        // Set by <content src="index.html" /> in config.xml
        super.appView.getSettings().setUserAgentString("GAITCordova;" + super.appView.getSettings().getUserAgentString());
        super.appView.addJavascriptInterface(new CustomNativeAccess(), "CustomNativeAccess");
        if (Intent.ACTION_VIEW.equals(getIntent().getAction())) {
            Logger.getLogger("CordovaLog").info("processing intent");
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

    private void processNFC(final Intent intent) {
        final Parcelable[] rawMsgs = intent.getParcelableArrayExtra(
        NfcAdapter.EXTRA_NDEF_MESSAGES);
        final NdefMessage msg = (NdefMessage) rawMsgs[0];
        Logger.getLogger("CordovaLog").info("OnProcessNFC" + msg.getRecords()[0].getPayload());
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

        Logger.getLogger("CordovaLog").info("processView: being");
        if ("bitcoin".equals(intent.getData().getScheme())) {
            Logger.getLogger("CordovaLog").info("processView: bitcoin uri");
            String uri = "/uri/?uri=" + Uri.encode(intent.getData().toString());
            Logger.getLogger("CordovaLog").info(getBaseURL() + "#" + uri);
            super.loadUrl(getBaseURL() + "#" + uri);
        } else if (intent.getData().getPath() == null) {
            Logger.getLogger("CordovaLog").info("processView: getPath == null");
            super.loadUrl(getBaseURL());
        } else {
            Logger.getLogger("CordovaLog").info("processView: else");
            String path = intent.getData().getPath();
            Logger.getLogger("CordovaLog").info("processView: PATH " + path);
            Logger.getLogger("CordovaLog").info("processView: int " + intent.toString());
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
                Logger.getLogger("CordovaLog").info("processView: should NEVER NEVER happen");
            }
        }
        Logger.getLogger("CordovaLog").info("processView: end.");
    }
    
    private void handleWidget(final Intent intent) {
        if (intent != null) {
            final String hash = intent.getStringExtra("hash");
            if (hash != null) {
                Logger.getLogger("CordovaLog").info("handleWidget " + hash);
         //       Logger.getLogger("CordovaLog").info("testing if redirecting properly " + getIntent().getBundle().toString());
                if (("/send".equals(hash) || "/receive".equals(hash))) {
                        final String js = "location.hash=\"#" +hash+"\"";
                        Logger.getLogger("CordovaLog").info("exec " + js);
                        super.sendJavascript(js);
                        /*
                        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
                            appView.loadUrl("javascript:location.hash=\"" +hash+"\"");
                            Logger.getLogger("CordovaLog").info("load");
                        } else {
                            Logger.getLogger("CordovaLog").info("eval");
                            appView.evaluateJavascript("location.hash=\"" +hash+"\"", null);
                        }
                        */
                        Logger.getLogger("CordovaLog").info("returning");
                }
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Logger.getLogger("CordovaLog").info("OnResume");
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            processNFC(getIntent());
        }
        /*
        for (String key : getIntent().getExtras().keySet()) {
                Object value = getIntent().getExtras().get(key);
                Logger.getLogger("CordovaLog").info(String.format("%s %s (%s)", key, value.toString(), value.getClass().getName()));
        }
        */
        Logger.getLogger("CordovaLog").info("OnResume action" + getIntent().getAction());
        if (Intent.ACTION_VIEW.equals(getIntent().getAction())) {    
            processView(getIntent());
        }
        handleWidget(lastIntent);
        if (lastIntent != null && Intent.ACTION_VIEW.equals(lastIntent.getAction())) {
            processView(lastIntent);
        }
        lastIntent = null;
        /*
        if (intent != null && intent.getExtras() != null)  {
            for (String key : intent.getExtras().keySet()) {
                    Object value = intent.getExtras().get(key);
                    Logger.getLogger("CordovaLog").info(String.format("onResume %s %s (%s)", key, value.toString(), value.getClass().getName()));
            }
        }
        */
    }

    @Override
    protected void onNewIntent(Intent intent) {
        lastIntent = intent;
        //processView(intent);
        Logger.getLogger("CordovaLog").info("onNewIntent - lawrence" + intent.toString());
        String hash = (intent.getData() == null? null : intent.getData().getPath());
        Logger.getLogger("CordovaLog").info("on NewIntent path - " + hash);
        Logger.getLogger("CordovaLog").info("onNewIntent - extras? " + intent.getExtras());
             //  final Intent prevIntent = getIntent();
       super.onNewIntent(intent);
       setIntent(intent);
    }
}
