package it.greenaddress.cordova;

import android.content.Intent;
import android.content.Context;
import android.app.Activity;
import org.apache.cordova.*;
import org.json.JSONArray;


public class PINInput extends CordovaPlugin {

	public static final int REQUEST_CODE = 0x0ba7c0de;

	CallbackContext lastCallbackContext;

	public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) {
		if ("show_input".equals(action)) {
			lastCallbackContext = callbackContext;
			
			Context context = cordova.getActivity().getApplicationContext();
		    Intent intent = new Intent(context, PINInputActivity.class);
		    cordova.startActivityForResult((CordovaPlugin)PINInput.this, intent, REQUEST_CODE);

			return true;
		} else {
			return false;
		}
	}

	@Override
	public void onActivityResult(int requestCode, int resultCode, Intent data) {
	 	super.onActivityResult(requestCode, resultCode, data);
	 	if (requestCode == REQUEST_CODE) {
		  	if (resultCode == Activity.RESULT_OK) {
	        	final PluginResult result = new PluginResult(PluginResult.Status.OK, data.getStringExtra("PIN"));
	            lastCallbackContext.sendPluginResult(result);
		  	} else {
	        	final PluginResult result = new PluginResult(PluginResult.Status.ERROR, "cancelled");
	            lastCallbackContext.sendPluginResult(result);
		  	}
		}
	}
}