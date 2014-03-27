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
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import java.util.logging.Logger;
import android.os.Parcelable;

public class GreenAddressIt extends CordovaActivity 
{
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
        // Set by <content src="index.html" /> in config.xml
        super.appView.getSettings().setUserAgentString("GAITCordova;" + super.appView.getSettings().getUserAgentString());
        if (Intent.ACTION_VIEW.equals(getIntent().getAction())) {
            processView(getIntent());
        } else {
            super.clearCache();
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
        return "https://greenaddress.it";
    }

    private void processView(final Intent intent) {
        if (getIntent().getData().getPath() == null) {
            super.loadUrl(getBaseURL());
        } else {
            super.loadUrl(getBaseURL() + getIntent().getData().getPath());
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Logger.getLogger("CordovaLog").info("OnResume");
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            processNFC(getIntent());
        }
        if (Intent.ACTION_VIEW.equals(getIntent().getAction())) {
            processView(getIntent());
        }
    }
}
