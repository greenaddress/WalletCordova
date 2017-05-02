package it.greenaddress.cordova;

import com.github.ghetolay.jwamp.WampWebSocket;
import com.github.ghetolay.jwamp.WampConnection;
import com.github.ghetolay.jwamp.utils.WaitResponse;
import com.github.ghetolay.jwamp.message.WampArguments;
import com.github.ghetolay.jwamp.utils.ResultListener;
import com.github.ghetolay.jwamp.jetty.WampJettyFactory;
import com.github.ghetolay.jwamp.message.SerializationException;
import java.util.concurrent.TimeoutException;
import com.github.ghetolay.jwamp.rpc.CallException;
import com.github.ghetolay.jwamp.UnsupportedWampActionException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;
import java.util.HashMap;
import java.security.SignatureException;
public class WalletClient {

    private final static String wsuri = "wss://prodwss.greenaddress.it/ws/inv";
    public class GaException extends RuntimeException {
    }

    private static String getToken() {
        BufferedReader br = null;
        final URLConnection connection;
        try {
            final URL uri = new URL("https://greenaddress.it/token/");
            connection = uri.openConnection();
        } catch(IOException e) {
            return "";
        }
        try {
            br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            final StringBuilder sb = new StringBuilder();
            String inputLine;

            while ((inputLine = br.readLine()) != null) {
                sb.append(inputLine);
            }

            return sb.toString();
        } catch(IOException e) {
            return "";
        } finally {
            if (br != null) {
                try {br.close();} catch(final IOException e) {}
            }
        }
    }

    private WampWebSocket wamp = null;
    private WampConnection connection = null;

    private void authenticate() {
        final String token = getToken();
        if (token == "") {
            throw new GaException();
        }


        WampJettyFactory wampFact = WampJettyFactory.getInstance();

        /*ResultListener<WampWebSocket> rl = new ResultListener<WampWebSocket>() {
            @Override
            public void onResult(WampWebSocket result) {

            }
        };*/

        WaitResponse<WampWebSocket> wr = new WaitResponse<WampWebSocket>(5000);
        try {
            connection = wampFact.connect(new URI(wsuri), wr);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }


        if(connection != null){
            try {
                wamp = wr.call();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }



        if (wamp == null) return;
        try {
            wamp.authenticate(token, token);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        } catch (UnsupportedWampActionException e) {
            e.printStackTrace();
        } catch (CallException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    public void login(final String username, final String password) {
        if (wamp == null) {
            authenticate();
        }
        if (wamp == null) {
            throw new GaException();
        }


        Map<String, String> loginData = new HashMap<String, String>();
        loginData.put("username", username);
        loginData.put("password", password);

        WampArguments loggedIn = null;

        try {
            loggedIn = wamp.simpleCall("http://greenaddressit.com/login/watch_only",
                "custom",
                loginData,
                false);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        } catch (UnsupportedWampActionException e) {
            e.printStackTrace();
        } catch (CallException e) {
            e.printStackTrace();
        }
    }

    public String getBalance() {

        WampArguments balance = null;

        try {
            balance = wamp.simpleCall("http://greenaddressit.com/txs/get_balance");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        } catch (UnsupportedWampActionException e) {
            e.printStackTrace();
        } catch (CallException e) {
            e.printStackTrace();
        }

        if (balance != null && balance.hasNext()) {
            String satoshis = "" + balance.nextObject().asMap().get("satoshi");
            return satoshis;
        }
        else  {
            return "";
        }

    }

    public void disconnect() {
            connection.close(1000, "logout");
    }

}
