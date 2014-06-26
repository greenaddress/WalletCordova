package it.greenaddress.cordova;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import java.nio.charset.Charset;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

public class BIP39 extends CordovaPlugin 
{
    private final static String HMAC = "HmacSHA512";

    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if ("calcSeed".equals(action)) {
            final long iterations = 2048;
            final byte[] salt = args.getString(0).getBytes(Charset.forName("UTF-8"));
            final byte[] password = args.getString(1).getBytes(Charset.forName("UTF-8"));
            
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    final byte[] salt_i = new byte[salt.length + 4];
                    for (int i = 0; i < salt.length; ++i) salt_i[i] = salt[i];
                    // append blockindex:
                    salt_i[salt.length] = 0;
                    salt_i[salt.length+1] = 0;
                    salt_i[salt.length+2] = 0;
                    salt_i[salt.length+3] = 1;
                    
                    try {
                        final byte[] block = PRF(password, salt_i);
                        long i = 1;
                        for (byte[] u = block.clone(); i < iterations; i++) {
                            u = PRF(password, u);
                            for (int j = 0; j < block.length; j++) block[j] ^= u[j];
                            
                            final long prevProgress = Math.round(100.0*i/iterations), curProgress = Math.round(100.0*(i+1)/iterations);
                            if (curProgress > prevProgress) {
                                final PluginResult result = new PluginResult(PluginResult.Status.OK, curProgress);
                                result.setKeepCallback(true);
                                callbackContext.sendPluginResult(result);
                            }
                        }
                        
                        PluginResult result = new PluginResult(PluginResult.Status.OK, block);
                        callbackContext.sendPluginResult(result);
                    } catch(final NoSuchAlgorithmException e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "NoSuchAlgorithm");
                        callbackContext.sendPluginResult(result);
                    } catch(final InvalidKeyException e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "InvalidKey");
                        callbackContext.sendPluginResult(result);
                    }
                    
                }
            });
            return true;
        }
        return false;
    }
    
    private byte[] PRF(byte[] password, byte[] salt) throws NoSuchAlgorithmException,
                                                            InvalidKeyException {
        final Mac mac = Mac.getInstance(HMAC);
        final SecretKeySpec secret_spec = new SecretKeySpec(password, HMAC);
        mac.init(secret_spec);
        return mac.doFinal(salt);
    }
}

