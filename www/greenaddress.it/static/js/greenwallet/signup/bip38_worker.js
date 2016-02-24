importScripts('/static/js/scrypt.js');
importScripts('/static/js/bitcoinjs.min.js');
GAIT_IN_WORKER = true;  // used inside bitcoinjs_util.js
importScripts('/static/js/bitcoinjs_util.js');
importScripts('/static/js/greenwallet/signup/bip38.js');
bitcoinBip38 = new Bitcoin.bip38();
onmessage = function(input) {
    var input = input.data;
    if (input.eckey) {
        cur_net = Bitcoin.bitcoin.networks[
            input.network == 'BTC' ? 'bitcoin' : 'testnet'
        ];
        bitcoinBip38.versions = {private: cur_net.wif};
        var ecpair = Bitcoin.bitcoin.ECPair.fromWIF(input.eckey, cur_net);
        // for compatibility with iOS, use mainnet bitcoin addr instead of testnet for salt:
        ecpair.network = Bitcoin.bitcoin.networks.bitcoin;
        postMessage(bitcoinBip38.encrypt(
            input.eckey,
            input.password,
            ecpair.getAddress()
        ));
    } else if (input.mnemonic_decrypted) {
        postMessage(bip38.encrypt({data: input.mnemonic_decrypted, key: input.password}, input.salt_a));
    } else if (input.mnemonic_encrypted) {
        postMessage(bip38.decrypt({data: input.mnemonic_encrypted, key: input.password}));
    } else {
        bitcoinBip38.versions = {private: input.cur_net_wif};
    	try {
            var decrypted = bitcoinBip38.decrypt(input.b58, input.password);
            postMessage(decrypted);
        } catch (e) {
            console.log(e);
        	if (e.message.indexOf("Hash could not be verified.") != -1) {
        		postMessage({error: 'invalid_passphrase'});
        	} else {
        		postMessage({error: 'invalid_privkey'});
        	}
        }
    }
}
