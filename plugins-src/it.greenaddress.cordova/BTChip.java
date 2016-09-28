package it.greenaddress.cordova;

import com.btchip.comm.BTChipTransport;
import com.btchip.BTChipDongle;
import com.btchip.utils.Dump;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;


public class BTChip extends CordovaPlugin
{
    public static BTChipTransport transport;
    public static int vendorId;

    boolean checkTransport(final CallbackContext callbackContext) {
        if (transport == null) {
            final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "Write failed");
            callbackContext.sendPluginResult(result);
            return false;
        } else {
            return true;
        }
    }

    void processException(final Exception e) {
        e.printStackTrace();
        if (e.getMessage().equals("Write failed")) {
            try {
                transport.close();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            transport = null;
        }
    }

    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if ("has_dongle".equals(action)) {
            final PluginResult result = new PluginResult(PluginResult.Status.OK, transport != null);
            callbackContext.sendPluginResult(result);
            return true;
        } else if ("disconnect".equals(action)) {
            // not useful on Android
            // transport.close();
        } else if ("getVendorId".equals(action)) {
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, vendorId));
            return true;
        } else if ("getFirmwareVersion".equals(action)) {
            if (!checkTransport(callbackContext)) return true;
            try {
                byte[] result_bytes = transport.exchange(Dump.hexToBin("e0c4000000"));
                final PluginResult result = new PluginResult(PluginResult.Status.OK, Dump.dump(result_bytes));
                callbackContext.sendPluginResult(result);
            } catch(Exception e) {
                final PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                callbackContext.sendPluginResult(result);
                processException(e);
            }
            return true;
        } else if ("verifyPin".equals(action)) {
            if (!checkTransport(callbackContext)) return true;
            try {
                BTChipDongle dongle = new BTChipDongle(transport);
                dongle.verifyPin(Dump.hexToBin(args.getString(0)));
                final PluginResult result = new PluginResult(PluginResult.Status.OK, true);
                callbackContext.sendPluginResult(result);
            } catch(Exception e) {
                final PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                callbackContext.sendPluginResult(result);
                processException(e);
            }
            return true;
        } else if ("getWalletPublicKey".equals(action)) {
            if (!checkTransport(callbackContext)) return true;
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        BTChipDongle dongle = new BTChipDongle(transport);
                        BTChipDongle.BTChipPublicKey key = dongle.getWalletPublicKey(args.getString(0));
                        JSONObject json = new JSONObject()
                            .put("publicKey", Dump.dump(key.getPublicKey()))
                            .put("chainCode", Dump.dump(key.getChainCode()))
                            .put("bitcoinAddress", key.getAddress());
                        final PluginResult result = new PluginResult(PluginResult.Status.OK, json);
                        callbackContext.sendPluginResult(result);
                    } catch(Exception e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        callbackContext.sendPluginResult(result);
                        processException(e);
                    }
                }
            });
            return true;
        } else if ("signMessagePrepare".equals(action)) {
            if (!checkTransport(callbackContext)) return true;
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        BTChipDongle dongle = new BTChipDongle(transport);
                        dongle.signMessagePrepare(args.getString(0), Dump.hexToBin(args.getString(1)));
                        final PluginResult result = new PluginResult(PluginResult.Status.OK, true);
                        callbackContext.sendPluginResult(result);
                    } catch(Exception e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        callbackContext.sendPluginResult(result);
                        processException(e);
                    }
                }
            });
            return true;
        } else if ("signMessageSign".equals(action)) {
            if (!checkTransport(callbackContext)) return true;
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        BTChipDongle dongle = new BTChipDongle(transport);
                        BTChipDongle.BTChipSignature signature = dongle.signMessageSign(Dump.hexToBin(args.getString(0)));

                        String hex = Dump.dump(signature.getSignature());
                        byte[] yParity = new byte[1];
                        yParity[0] = (byte)signature.getYParity();
                        hex = Dump.dump(yParity) + hex.substring(2);
                        final PluginResult result = new PluginResult(PluginResult.Status.OK, hex);
                        callbackContext.sendPluginResult(result);
                    } catch(Exception e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        callbackContext.sendPluginResult(result);
                        processException(e);
                    }
                }
            });
            return true;
        } else if ("startUntrustedTransaction".equals(action)) {
            if (!checkTransport(callbackContext)) return true;
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        BTChipDongle dongle = new BTChipDongle(transport);
                        JSONArray inputs_json = args.getJSONArray(2);
                        BTChipDongle.BTChipInput[] inputs = new BTChipDongle.BTChipInput[inputs_json.length()];
                        for (int i = 0; i < inputs_json.length(); i++) {
                            byte[] outpoint = Dump.hexToBin(inputs_json.getString(i).substring(0, 72));
                            byte[] sequence = Dump.hexToBin(inputs_json.getString(i).substring(72, 80));
                            inputs[i] = dongle.createInput(outpoint, sequence, false);
                        }
                        dongle.startUntrustedTransaction(args.getBoolean(0), args.getLong(1), inputs, Dump.hexToBin(args.getString(3)));
                        final PluginResult result = new PluginResult(PluginResult.Status.OK, true);
                        callbackContext.sendPluginResult(result);
                    } catch(Exception e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        callbackContext.sendPluginResult(result);
                        processException(e);
                    }
                }
            });
            return true;
        } else if ("finalizeInputFull".equals(action)) {
            if (!checkTransport(callbackContext)) return true;
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        BTChipDongle dongle = new BTChipDongle(transport);
                        dongle.finalizeInputFull(Dump.hexToBin(args.getString(0)));
                        final PluginResult result = new PluginResult(PluginResult.Status.OK, true);
                        callbackContext.sendPluginResult(result);
                    } catch(Exception e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        callbackContext.sendPluginResult(result);
                        processException(e);
                    }
                }
            });
            return true;
        } else if ("untrustedHashSign".equals(action)) {
            if (!checkTransport(callbackContext)) return true;
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        BTChipDongle dongle = new BTChipDongle(transport);
                        byte[] signature = dongle.untrustedHashSign(args.getString(0), "0", (long)args.getLong(1), (byte)1);
                        final PluginResult result = new PluginResult(PluginResult.Status.OK, Dump.dump(signature));
                        callbackContext.sendPluginResult(result);
                    } catch(Exception e) {
                        final PluginResult result = new PluginResult(PluginResult.Status.ERROR, e.toString());
                        callbackContext.sendPluginResult(result);
                        processException(e);
                    }
                }
            });
            return true;
        }
        return false;
    }
}

