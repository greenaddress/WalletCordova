package it.greenaddress.cordova;

import android.preference.PreferenceActivity;
import android.os.Bundle;
import android.appwidget.AppWidgetManager;
import android.content.ComponentName;



public class SettingsActivity extends PreferenceActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.widget_preferences);
    }
    @Override
    public void onStop() {
        super.onStop();
        final AppWidgetManager appWidgetManager = AppWidgetManager.getInstance(this);

        final ComponentName providerName = new ComponentName(this, WalletBalanceWidgetProvider.class);

        try
        {
            final int[] appWidgetIds = appWidgetManager.getAppWidgetIds(providerName);

            if (appWidgetIds.length > 0)
            {
                WalletBalanceWidgetProvider.runAsyncTask(this, appWidgetManager, appWidgetIds);
            }
        }
        catch (final RuntimeException x)
        {
        }
    }
}
