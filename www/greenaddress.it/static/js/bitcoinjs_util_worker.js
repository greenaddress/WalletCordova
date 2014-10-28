try { importScripts('typedarray.js'); } catch (e) { }  // Cordova polyfill
importScripts('bitcoinjs.min.js');
funcs = {
	derive: function(data, cb) {
		var wallet = Bitcoin.HDWallet.fromBase58(data.wallet);
		return wallet.derive(data.i).toBase58(wallet.priv);
	},
	sign: function(data, cb) {
		var key = new Bitcoin.ECKey(data.key);
		return key.sign(data.hash);
	}
}
onmessage = function(message) {
	postMessage({
		callId: message.data.callId,
		result: funcs[message.data.func](message.data.data)
	});
}