package it.greenaddress.cordova;

import android.os.Bundle;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.EditText;
import android.widget.Button;
import android.text.InputType;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.view.inputmethod.EditorInfo;


public class PINInputActivity extends Activity {

	protected LinearLayout root;

	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		root = new LinearLayout(this);
		root.setOrientation(LinearLayout.VERTICAL);

		final TextView text = new TextView(this);
		text.setText("Please enter your PIN:");
		text.setTextSize(TypedValue.COMPLEX_UNIT_DIP, 24);
		text.setTextAlignment(TextView.TEXT_ALIGNMENT_CENTER);

		final EditText pinInput = new EditText(this);
		pinInput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);

		final LinearLayout buttons = new LinearLayout(this);
		final Button cancel = new Button(this);
		cancel.setText("Cancel");
		final Button login = new Button(this);
		login.setText("Login");
		buttons.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.FILL_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
		cancel.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1));
		login.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1));
		buttons.addView(cancel);		
		buttons.addView(login);

		login.setId(1);
		pinInput.setNextFocusDownId(login.getId());

		root.addView(text);
		root.addView(pinInput);
		root.addView(buttons);

		setContentView(root);

		this.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);

        login.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
            	Intent output = new Intent();
            	output.putExtra("PIN", pinInput.getText().toString());
                PINInputActivity.this.setResult(Activity.RESULT_OK, output);
                PINInputActivity.this.finish();
            }
        });

        pinInput.setOnEditorActionListener(new TextView.OnEditorActionListener() {
        	@Override
        	public boolean onEditorAction (TextView v, int actionId, KeyEvent event) {
        		if ((actionId & EditorInfo.IME_ACTION_DONE) == EditorInfo.IME_ACTION_DONE) {
        			Intent output = new Intent();
	            	output.putExtra("PIN", pinInput.getText().toString());
	                PINInputActivity.this.setResult(Activity.RESULT_OK, output);
	                PINInputActivity.this.finish();
	                return true;
        		}
        		return false;
        	}
        });

        cancel.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                PINInputActivity.this.setResult(Activity.RESULT_CANCELED);
                PINInputActivity.this.finish();
            }
        });
	}
}