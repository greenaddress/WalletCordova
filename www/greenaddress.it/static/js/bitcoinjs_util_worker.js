try { importScripts('typedarray.js'); } catch (e) { }  // Cordova polyfill
importScripts('secp256k1.js');
importScripts('bitcoinjs.min.js');
Module.secp256k1ctx = Module._secp256k1_context_create(3);

try {
    var randArr = new Uint8Array(32);
    window.crypto.getRandomValues(randArr);
    if (!Module._secp256k1_context_randomize(Module.secp256k1ctx, randArr)) {
        throw new Error("Couldn't initialize library, randomized failed");
    }
} catch (e) { }  // firefox doesn't find window nor crypto?


Bitcoin.ECKey.prototype.getPub = function(compressed) {
    if (compressed === undefined) compressed = this.compressed;

    var out = Module._malloc(128);
    var out_s = Module._malloc(4);
    var secexp = Module._malloc(32);
    var start = this.priv.toByteArray().length - 32;
    if (start >= 0) {  // remove excess zeroes
        var slice = this.priv.toByteArray().slice(start);
    } else {  // add missing zeroes
        var slice = this.priv.toByteArray();
        while (slice.length < 32) slice.unshift(0);
    }
    writeArrayToMemory(slice, secexp);
    setValue(out_s, 128, 'i32');

    Module._secp256k1_ec_pubkey_create(Module.secp256k1ctx, out, out_s, secexp, compressed ? 1 : 0);

    var ret = [];
    for (var i = 0; i < getValue(out_s, 'i32'); ++i) {
        ret[i] = getValue(out+i, 'i8') & 0xff;
    }

    Module._free(out);
    Module._free(out_s);
    Module._free(secexp);

    return Bitcoin.ECPubKey(ret, compressed)
};
funcs = {
	derive: function(data, cb) {
		var wallet = Bitcoin.HDWallet.fromBase58(data.wallet);
		return wallet.derive(data.i).toBase58(wallet.priv);
	},
	sign: function(data, cb) {
		var key = new Bitcoin.ECKey(data.key);

        var sig = Module._malloc(128);
        var siglen_p = Module._malloc(4);
        var msg = Module._malloc(32);
        var seckey = Module._malloc(32);
        var start = key.priv.toByteArray().length - 32;
        if (start >= 0) {  // remove excess zeroes
            var slice = key.priv.toByteArray().slice(start);
        } else {  // add missing zeroes
            var slice = key.priv.toByteArray();
            while (slice.length < 32) slice.unshift(0);
        }
        writeArrayToMemory(slice, seckey);
        setValue(siglen_p, 128, 'i32');
        for (var i = 0; i < 32; ++i) {
            setValue(msg + i, data.hash[i], 'i8');
        }

        Module._secp256k1_ecdsa_sign(Module.secp256k1ctx, msg, sig, siglen_p, seckey, 0, 0);

        var ret = [];
        for (var i = 0; i < getValue(siglen_p, 'i32'); ++i) {
            ret[i] = getValue(sig+i, 'i8') & 0xff;
        }

        Module._free(sig);
        Module._free(siglen_p);
        Module._free(msg);
        Module._free(seckey);

        return ret;
	}
}
onmessage = function(message) {
	postMessage({
		callId: message.data.callId,
		result: funcs[message.data.func](message.data.data)
	});
}
