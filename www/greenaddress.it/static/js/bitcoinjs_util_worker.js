try { importScripts('typedarray.js'); } catch (e) { }  // Cordova polyfill
importScripts('bitcoinjs.min.js');

try {
    var randArr = new Uint8Array(32);
    window.crypto.getRandomValues(randArr);
    if (!Module._secp256k1_context_randomize(Module.secp256k1ctx, randArr)) {
        throw new Error("Couldn't initialize library, randomized failed");
    }
} catch (e) { }  // firefox doesn't find window nor crypto?

var isPatched = false;
var patchIfNotPatched = function(isAlpha) {
    if (isPatched) return;
    isPatched = true;
    if (isAlpha) {
        importScripts('secp256k1-alpha/secp256k1-alpha.js');
        Bitcoin.contrib.init_secp256k1(Module, isAlpha);
        // TODO: implementation of getPublicKeyBuffer for alpha's libsecp256k1
        return;
    } else {
        importScripts('secp256k1.js');
        Bitcoin.contrib.init_secp256k1(Module, isAlpha);
    }
}
// segnet hack (belongs in bitcoinjs really)
segnet = {pubKeyHash: 30, scriptHash: 50, wif: 158,
          bip32: {public: 0x053587CF, private: 0x05358394},
          messagePrefix: '\x18Bitcoin Signed Message:\n',
          dustThreshold: 546};
funcs = {
	derive: function(data, isAlpha) {
		var wallet = Bitcoin.bitcoin.HDNode.fromBase58(
            data.wallet,
            [Bitcoin.bitcoin.networks.bitcoin,
             Bitcoin.bitcoin.networks.testnet,
             segnet]
        );
		return wallet.derive(data.i).toBase58();
	},
	sign: function(data, isAlpha, schnorr) {
		var key = Bitcoin.bitcoin.ECPair.fromWIF(
            data.key,
            [Bitcoin.bitcoin.networks.bitcoin,
             Bitcoin.bitcoin.networks.testnet,
             segnet]
        );

        if (schnorr) {
            var sig = Module._malloc(64);
        } else {
            var sig = Module._malloc(128);
            var siglen_p = Module._malloc(4);
        }
        var msg = Module._malloc(32);
        var seckey = Module._malloc(32);
        var start = key.d.toByteArray().length - 32;
        if (start >= 0) {  // remove excess zeroes
            var slice = key.d.toByteArray().slice(start);
        } else {  // add missing zeroes
            var slice = key.d.toByteArray();
            while (slice.length < 32) slice.unshift(0);
        }
        writeArrayToMemory(slice, seckey);
        if (!schnorr) {
            setValue(siglen_p, 128, 'i32');
        }
        for (var i = 0; i < 32; ++i) {
            setValue(msg + i, data.hash[i], 'i8');
        }

        if (schnorr) {
            if (1 != Module._secp256k1_schnorr_sign(Module.secp256k1ctx, sig, msg, seckey, 0, 0)) {
                throw new Error('secp256k1 Schnorr sign failed');
            };
            var len = 64;
        } else {
            var sig_opaque = Module._malloc(64);
            if (1 != Module._secp256k1_ecdsa_sign(Module.secp256k1ctx, sig_opaque, msg, seckey, 0, 0)) {
                throw new Error('secp256k1 ECDSA sign failed');
            }
            if (1 != Module._secp256k1_ecdsa_signature_serialize_der(Module.secp256k1ctx, sig, siglen_p, sig_opaque)) {
                throw new Error('secp256k1 ECDSA signature serialize failed');
            }
            var len = getValue(siglen_p, 'i32');
            Module._free(sig_opaque);
        }
        var ret = [];
        for (var i = 0; i < len; ++i) {
            ret[i] = getValue(sig+i, 'i8') & 0xff;
        }

        Module._free(sig);
        if (!schnorr) {
            Module._free(siglen_p);
        }
        Module._free(msg);
        Module._free(seckey);

        return ret;
	}
}
onmessage = function(message) {
  patchIfNotPatched(message.data.isAlpha);
	postMessage({
		callId: message.data.callId,
		result: funcs[message.data.func](
        message.data.data,
        message.data.isAlpha,
        message.data.schnorr
    )
	});
}
