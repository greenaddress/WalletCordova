/*
 * Copyright 2011-2014 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package it.greenaddress.cordova;

import android.app.PendingIntent;
import android.net.Uri;
import android.net.Uri.Builder;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.preference.PreferenceManager;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.Spannable;
import android.widget.RemoteViews;
import android.os.AsyncTask;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;
import java.util.HashMap;
import java.security.SignatureException;

import android.content.SharedPreferences;
import java.util.logging.Logger;
import it.greenaddress.cordova.R;
import android.text.style.RelativeSizeSpan;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import android.graphics.Typeface;
import java.util.Locale;

import android.text.style.StyleSpan;


import java.math.BigInteger;


/**
 * @author Andreas Schildbach
 */
public class WalletBalanceWidgetProvider extends AppWidgetProvider
{
        public static void runAsyncTask(final Context context, final AppWidgetManager appWidgetManager, final int[] appWidgetIds) {
            final AsyncTask wamp = new AsyncTask<Context, Void, String>() {

                @Override
                protected String doInBackground(Context... contextPararm) {
                    final SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(context);
                    final String user = sharedPref.getString("username", "");
                    final String password = sharedPref.getString("password", "");
                    if (user == "" || password == "") {
                        return "";
                    }
                    final WalletClient wallet = new WalletClient();
                    try {
                        wallet.login(user, password);
                        return wallet.getBalance();
                    }
                    catch(Exception e) {
                    }
                    finally {
                        try {
                            wallet.disconnect();
                        } catch (Exception e) {
                        }
                    }
                    return "";
                }

                @Override
                protected void onPostExecute(String tokenParam) {
                    if (tokenParam != "") {
                        WalletBalanceWidgetProvider.updateWidgetsBalance(context, appWidgetManager, appWidgetIds, new BigInteger(tokenParam));
                    } else {
                        final Editable balanceStr = new SpannableStringBuilder("");
                        WalletBalanceWidgetProvider.updateWidgetsError(context, appWidgetManager, appWidgetIds, balanceStr);
                    }
                }
            }.execute(context);
        }

	@Override
	public void onUpdate(final Context context, final AppWidgetManager appWidgetManager, final int[] appWidgetIds)
	{
            WalletBalanceWidgetProvider.runAsyncTask(context, appWidgetManager, appWidgetIds);
	}
        private static final Pattern P_SIGNIFICANT = Pattern.compile("^([-+]" + '\u2009' + ")?\\d*(\\.\\d{0,2})?");
        private static final Object SIGNIFICANT_SPAN = new StyleSpan(Typeface.BOLD);
        public static final BigInteger ONE_BTC = new BigInteger("100000000", 10);
        public static final BigInteger ONE_MBTC = new BigInteger("100000", 10);
        public static final BigInteger ONE_UBTC = new BigInteger("100", 10);

        private static final int ONE_BTC_INT = ONE_BTC.intValue();
        private static final int ONE_MBTC_INT = ONE_MBTC.intValue();
        private static final int ONE_UBTC_INT = ONE_UBTC.intValue();

        private static void formatSignificant(Editable s) {
                RelativeSizeSpan insignificantRelativeSizeSpan = new RelativeSizeSpan(0.85f);
                s.removeSpan(SIGNIFICANT_SPAN);
                s.removeSpan(insignificantRelativeSizeSpan);
                final Matcher m = P_SIGNIFICANT.matcher(s);
                if (m.find())
                {
                    final int pivot = m.group().length();
                    s.setSpan(SIGNIFICANT_SPAN, 0, pivot, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                    if (s.length() > pivot)
                    s.setSpan(insignificantRelativeSizeSpan, pivot, s.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                }

        }
	public static String formatValue(final BigInteger value,
			final int precision, final int shift)
	{
                final String plusSign = "";
                final String minusSign = "-";
		long longValue = value.longValue();

		final String sign = longValue < 0 ? minusSign : plusSign;

		if (shift == 0)
		{
			if (precision == 2)
				longValue = longValue - longValue % 1000000 + longValue % 1000000 / 500000 * 1000000;
			else if (precision == 4)
				longValue = longValue - longValue % 10000 + longValue % 10000 / 5000 * 10000;
			else if (precision == 6)
				longValue = longValue - longValue % 100 + longValue % 100 / 50 * 100;
			else if (precision == 8)
				;
			else
				throw new IllegalArgumentException("cannot handle precision/shift: " + precision + "/" + shift);

			final long absValue = Math.abs(longValue);
			final long coins = absValue / ONE_BTC_INT;
			final int satoshis = (int) (absValue % ONE_BTC_INT);

			if (satoshis % 1000000 == 0)
				return String.format(Locale.US, "%s%d.%02d", sign, coins, satoshis / 1000000);
			else if (satoshis % 10000 == 0)
				return String.format(Locale.US, "%s%d.%04d", sign, coins, satoshis / 10000);
			else if (satoshis % 100 == 0)
				return String.format(Locale.US, "%s%d.%06d", sign, coins, satoshis / 100);
			else
				return String.format(Locale.US, "%s%d.%08d", sign, coins, satoshis);
		}
		else if (shift == 3)
		{
			if (precision == 2)
				longValue = longValue - longValue % 1000 + longValue % 1000 / 500 * 1000;
			else if (precision == 4)
				longValue = longValue - longValue % 10 + longValue % 10 / 5 * 10;
			else if (precision == 5)
				;
			else
				throw new IllegalArgumentException("cannot handle precision/shift: " + precision + "/" + shift);

			final long absValue = Math.abs(longValue);
			final long coins = absValue / ONE_MBTC_INT;
			final int satoshis = (int) (absValue % ONE_MBTC_INT);

			if (satoshis % 1000 == 0)
				return String.format(Locale.US, "%s%d.%02d", sign, coins, satoshis / 1000);
			else if (satoshis % 10 == 0)
				return String.format(Locale.US, "%s%d.%04d", sign, coins, satoshis / 10);
			else
				return String.format(Locale.US, "%s%d.%05d", sign, coins, satoshis);
		}
		else if (shift == 6)
		{
			if (precision == 0)
				longValue = longValue - longValue % 100 + longValue % 100 / 50 * 100;
			else if (precision == 2)
				;
			else
				throw new IllegalArgumentException("cannot handle precision/shift: " + precision + "/" + shift);

			final long absValue = Math.abs(longValue);
			final long coins = absValue / ONE_UBTC_INT;
			final int satoshis = (int) (absValue % ONE_UBTC_INT);

			if (satoshis % 100 == 0)
				return String.format(Locale.US, "%s%d", sign, coins);
			else
				return String.format(Locale.US, "%s%d.%02d", sign, coins, satoshis);
		}
		else
		{
			throw new IllegalArgumentException("cannot handle shift: " + shift);
		}
	}

	public static void updateWidgetsBalance(final Context context, final AppWidgetManager appWidgetManager, final int[] appWidgetIds,
			final BigInteger balance)
	{
		final Editable balanceStr = new SpannableStringBuilder(WalletBalanceWidgetProvider.formatValue(balance, 2, 3));
	        WalletBalanceWidgetProvider.formatSignificant(balanceStr);
                WalletBalanceWidgetProvider.updateWidgetsError(context, appWidgetManager, appWidgetIds, balanceStr);
        }

        public static Intent getGreenAddressIntent(final Context context, final String path) {
                final Intent i = new Intent(context, GreenAddressIt.class);
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_SINGLE_TOP);
                i.putExtra("hash", path);
                return i;
        }

	public static void updateWidgetsError(final Context context, final AppWidgetManager appWidgetManager, final int[] appWidgetIds,
			final Editable balanceStr)
	{
		for (final int appWidgetId : appWidgetIds)
		{
			final RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.wallet_balance_widget_content);
			views.setTextViewText(R.id.widget_wallet_prefix, "mBTC");
			views.setTextViewText(R.id.widget_wallet_balance, balanceStr);

			views.setOnClickPendingIntent(R.id.widget_button_balance,
					PendingIntent.getActivity(context, 0, new Intent(context, SettingsActivity.class), 0));

			views.setOnClickPendingIntent(R.id.widget_button_request,
					PendingIntent.getActivity(context, 0, getGreenAddressIntent(context, "/receive"), PendingIntent.FLAG_UPDATE_CURRENT));
			views.setOnClickPendingIntent(R.id.widget_button_send,
					PendingIntent.getActivity(context, 1, getGreenAddressIntent(context, "/send"), PendingIntent.FLAG_UPDATE_CURRENT));
			views.setOnClickPendingIntent(R.id.widget_button_send_qr,
					PendingIntent.getActivity(context, 2, getGreenAddressIntent(context, "/send"), PendingIntent.FLAG_UPDATE_CURRENT));

			appWidgetManager.updateAppWidget(appWidgetId, views);
		}
	}
}
