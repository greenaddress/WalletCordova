importScripts('/static/js/scrypt.js');
importScripts('/static/js/bitcoinjs.min.js');
GAIT_IN_WORKER = true;  // used inside bitcoinjs_util.js
importScripts('/static/js/bitcoinjs_util.js');
importScripts('/static/js/greenwallet/signup/bip38.js');
onmessage = function(input) {
    var input = input.data;
    if (input.eckey) {
        postMessage(new Bitcoin.ECKey(input.eckey).getEncryptedFormat(input.password, input.network));
    } else if (input.mnemonic_decrypted) {
        postMessage(bip38.encrypt({data: input.mnemonic_decrypted, key: input.password}, input.salt_a));
    } else if (input.mnemonic_encrypted) {
        postMessage(bip38.decrypt({data: input.mnemonic_encrypted, key: input.password}));
    } else {
    	try {
            postMessage(Bitcoin.ECKey.decodeEncryptedFormat(input.b58, input.password, input.cur_net).toWif());
        } catch (e) {
        	if (e.message.indexOf("Hash could not be verified.") != -1) {
        		postMessage({error: 'invalid_passphrase'});
        	} else {
        		postMessage({error: 'invalid_privkey'});
        	}
        }
    }
}
