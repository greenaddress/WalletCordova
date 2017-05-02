/**
*Copyright [2012] [Ghetolay]
*
*Licensed under the Apache License, Version 2.0 (the "License");
*you may not use this file except in compliance with the License.
*You may obtain a copy of the License at
*
*http://www.apache.org/licenses/LICENSE-2.0
*
*Unless required by applicable law or agreed to in writing, software
*distributed under the License is distributed on an "AS IS" BASIS,
*WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*See the License for the specific language governing permissions and
*limitations under the License.
*/
package com.github.ghetolay.jwamp.jetty;


import java.net.URI;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.eclipse.jetty.websocket.WebSocketClient;
import org.eclipse.jetty.websocket.WebSocketClientFactory;

import com.github.ghetolay.jwamp.WampConnection;
import com.github.ghetolay.jwamp.WampConnection.ReconnectPolicy;
import com.github.ghetolay.jwamp.WampFactory;
import com.github.ghetolay.jwamp.WampMessageHandler;
import com.github.ghetolay.jwamp.WampParameter;
import com.github.ghetolay.jwamp.utils.ResultListener;

public class WampJettyFactory extends WampFactory{
	
	private static WampJettyFactory instance;
	
	private WebSocketClientFactory fact = new WebSocketClientFactory();
	
	private WampJettyFactory(){}
	
	public WebSocketClientFactory getJettyFactory() {
		return fact;
	}

	public void setJettyFactory(WebSocketClientFactory fact) {
		this.fact = fact;
	}
		
	protected WampConnection getConnection(URI uri, long timeout, ReconnectPolicy reconnectPolicy, Collection<WampMessageHandler> handlers, ResultListener<WampConnection> wr) throws TimeoutException, Exception{
		JettyConnection connection = new JettyConnection(uri,getSerializer(),handlers,wr);
		connection.setReconnectPolicy(reconnectPolicy);
		
		connect(uri, timeout, connection);
		
		return connection;
	}
	
	protected void connect(URI uri, long timeout, JettyConnection connection) throws Exception{	
		if(!fact.isStarted())
			fact.start();
			
		WebSocketClient ws = fact.newWebSocketClient();
		ws.setProtocol(getProtocolName());
		
		if(timeout > 0)
			ws.open(uri, connection, timeout, TimeUnit.MILLISECONDS);
		else
			ws.open(uri,connection);
	}
	
	
	public static WampJettyFactory getInstance(){
		if(instance == null)
			instance = new WampJettyFactory();
		
		return instance;
	}
}
