package it.greenaddress.cordova;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import java.nio.charset.Charset;
import com.bitsofproof.supernode.common.Hash;
import com.bitsofproof.supernode.common.ECKeyPair;
import com.bitsofproof.supernode.common.ValidationException;
import com.bitsofproof.supernode.wallet.KeyFormatter;
import com.bitsofproof.supernode.api.Network;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import com.lambdaworks.crypto.SCrypt;

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
            final byte[] key = new byte[32];
            for (int i = 0; i < 32; ++i) key[i] = (byte)key_json.getInt(i);
            
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
                    PluginResult result = new PluginResult(PluginResult.Status.OK, keyPair.toString());
                    callbackContext.sendPluginResult(result);
                }
            });
            return true;
        } else if ("encrypt_raw".equals(action)) {
            final JSONArray data_json = args.getJSONArray(0);
            final byte[] data = new byte[32];
            for (int i = 0; i < 32; ++i) data[i] = (byte)data_json.getInt(i);
            final String password = args.getString(1);

            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    byte[] hash = Hash.hash(data), salt = new byte[4];
                    System.arraycopy (hash, 0, salt, 0, 4);
                    byte[] encrypted;
                    try {
                        byte[] derived;
                        derived = SCrypt.scrypt(password.getBytes("UTF-8"), salt, 16384, 8, 8, 64);
                        byte[] key = new byte[32];
                        System.arraycopy (derived, 32, key, 0, 32);
                        SecretKeySpec keyspec = new SecretKeySpec (key, "AES");
                        Cipher cipher = Cipher.getInstance ("AES/ECB/NoPadding", "BC");
                        cipher.init (Cipher.ENCRYPT_MODE, keyspec);
                        for ( int i = 0; i < 32; ++i )
                        {
                            data[i] ^= derived[i];
                        }
                        encrypted = cipher.doFinal (data, 0, 32);
                    } catch ( NoSuchPaddingException e ) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "no such padding");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( InvalidKeyException e ) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "invalid key");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( IllegalBlockSizeException e ) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "illegal block size");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( UnsupportedEncodingException e ) { 
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "unsupported encoding");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( NoSuchAlgorithmException e ) { 
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "no such algorithm");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( BadPaddingException e ) { 
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "bad padding");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( GeneralSecurityException e ) { 
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "general security exception");
                        callbackContext.sendPluginResult(result);
                        return;
                    }

                    final JSONArray json = new JSONArray();
                    byte[] result_bytes = new byte[36];
                    System.arraycopy (encrypted, 0, result_bytes, 0, 32);
                    System.arraycopy (salt, 0, result_bytes, 32, 4);
                    for (int i = 0; i < 36; i++) {
                        int ubyte = result_bytes[i];
                        ubyte &= 0xFF;
                        json.put(ubyte);
                    }
                    PluginResult result = new PluginResult(PluginResult.Status.OK, json);
                    callbackContext.sendPluginResult(result);            
                }
            });

            return true;
        } else if ("decrypt_raw".equals(action)) {
            final JSONArray data_json = args.getJSONArray(0);
            final byte[] data = new byte[36];
            for (int i = 0; i < 36; ++i) data[i] = (byte)data_json.getInt(i);
            final String password = args.getString(1);

            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    byte[] salt = new byte[4];
                    System.arraycopy (data, 32, salt, 0, 4);
                    byte[] derived, decrypted;
                    try {
                        derived = SCrypt.scrypt(password.getBytes("UTF-8"), salt, 16384, 8, 8, 64);
                        byte[] key = new byte[32];
                        System.arraycopy (derived, 32, key, 0, 32);
                        SecretKeySpec keyspec = new SecretKeySpec (key, "AES");
                        Cipher cipher = Cipher.getInstance ("AES/ECB/NoPadding", "BC");
                        cipher.init (Cipher.DECRYPT_MODE, keyspec);
                        decrypted = cipher.doFinal (data, 0, 32);
                    } catch ( NoSuchPaddingException e ) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "no such padding");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( InvalidKeyException e ) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "invalid key");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( IllegalBlockSizeException e ) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "illegal block size");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( UnsupportedEncodingException e ) { 
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "unsupported encoding");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( NoSuchAlgorithmException e ) { 
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "no such algorithm");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( BadPaddingException e ) { 
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "bad padding");
                        callbackContext.sendPluginResult(result);
                        return;
                    } catch ( GeneralSecurityException e ) { 
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "general security exception");
                        callbackContext.sendPluginResult(result);
                        return;
                    }
                    for ( int i = 0; i < 32; ++i )
                    {
                        decrypted[i] ^= derived[i];
                    }

                    byte[] hash = Hash.hash(decrypted);
                    for (int i = 0; i < 4; ++i) {
                        if (hash[i] != salt[i]) {
                            final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "invalid password");
                            callbackContext.sendPluginResult(result);
                            return;
                        }
                    }

                    final JSONArray json = new JSONArray();
                    for (int i = 0; i < decrypted.length; i++) {
                        int ubyte = decrypted[i];
                        ubyte &= 0xFF;
                        json.put(ubyte);
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

