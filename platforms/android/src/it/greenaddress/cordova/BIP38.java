package it.greenaddress.cordova;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import java.nio.charset.Charset;
import com.bitsofproof.supernode.common.ECKeyPair;
import com.bitsofproof.supernode.common.ValidationException;
import com.bitsofproof.supernode.wallet.KeyFormatter;
import com.bitsofproof.supernode.api.Network;

public class BIP38 extends CordovaPlugin 
{

    private Network coinToNetwork(final String cur_coin, final CallbackContext callbackContext) {
        if (cur_coin.equals("BTC")) return Network.PRODUCTION;
        else if (cur_coin.equals("BTT")) return Network.TEST;
        else {
            final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "InvalidNetwork");
            callbackContext.sendPluginResult(result);
            return null;
        }
    }

    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if ("encrypt".equals(action)) {
            final JSONArray key_json = args.getJSONArray(0);
            final byte[] key = new byte[key_json.length()];
            for (int i = 0; i < key_json.length(); ++i) key[i] = (byte)key_json.getInt(i);
            
            final String password = args.getString(1);
            final String cur_coin = args.getString(2);
            final Network network = coinToNetwork(cur_coin, callbackContext);
            if (network == null) return true;
            
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    final ECKeyPair keyPair;
                    try {
                        keyPair = new ECKeyPair(key, true);  // compressed=true
                    } catch(final ValidationException e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "ValidationException");
                        callbackContext.sendPluginResult(result);
                        return;
                    }

                    final KeyFormatter kf = new KeyFormatter(password, network);
                    final String serializedKey;
                    try {
                        serializedKey = kf.serializeKey(keyPair);
                    } catch(final ValidationException e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "ValidationException");
                        callbackContext.sendPluginResult(result);
                        return;
                    }
                    PluginResult result = new PluginResult(PluginResult.Status.OK, serializedKey);
                    callbackContext.sendPluginResult(result);
                }
            });
            return true;
        } else if ("decrypt".equals(action)) {
            final String b58 = args.getString(0);
            final String password = args.getString(1);
            final String cur_coin = args.getString(2);
            final Network network = coinToNetwork(cur_coin, callbackContext);
            if (network == null) return true;

            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    final KeyFormatter kf = new KeyFormatter(password, network);
                    final ECKeyPair keyPair;
                    try {
                        keyPair = kf.parseSerializedKey(b58);
                    } catch(final ValidationException e) {
                        final String message;
                        if (e.getMessage().equals("invalid key")) message = "invalid_privkey";
                        else if (e.getMessage().equals("checksum mismatch")) message = "invalid_privkey";
                        // decrpyt typo in com.bitsofproof.supernode.wallet.KeyFormatter
                        else if (e.getMessage().equals("failed to decrpyt")) message = "invalid_passphrase";
                        else message = e.getMessage();
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, message);
                        callbackContext.sendPluginResult(result);
                        return;
                    }
                    final JSONArray json = new JSONArray();
                    for (int i = 0; i < keyPair.getPrivate().length; i++) {
                        json.put(keyPair.getPrivate()[i]);
                    }
                    PluginResult result = new PluginResult(PluginResult.Status.OK, json);
                    callbackContext.sendPluginResult(result);
                }
            });
            return true;
        }
        return false;
    }
}

