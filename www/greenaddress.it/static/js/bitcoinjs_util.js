// Bitcoin utility functions
Bitcoin.Util = {
    /**
     * Parse a Bitcoin value byte array, returning a BigInteger.
     */
    valueToBigInt: function (valueBuffer)
    {
        if (valueBuffer instanceof Bitcoin.BigInteger) return valueBuffer;

        // Prepend zero byte to prevent interpretation as negative integer
        return Bitcoin.BigInteger.fromByteArrayUnsigned(valueBuffer);
    },

    /**
     * Format a Bitcoin value as a string.
     *
     * Takes a BigInteger or byte-array and returns that amount of Bitcoins in a
     * nice standard formatting.
     *
     * Examples:
     * 12.3555
     * 0.1234
     * 900.99998888
     * 34.00
     */
    formatValue: function (valueBuffer) {
        var value = this.valueToBigInt(valueBuffer).toString();

        var integerPart = value.length > 8 ? value.substr(0, value.length-8) : '0';
        var decimalPart = value.length > 8 ? value.substr(value.length-8) : value;

        while (decimalPart.length < 8) decimalPart = "0"+decimalPart;
        decimalPart = decimalPart.replace(/0*$/, '');
        while (decimalPart.length < 2) decimalPart += "0";
        return integerPart+"."+decimalPart;
    },

    /**
     * Parse a floating point string as a Bitcoin value.
     *
     * Keep in mind that parsing user input is messy. You should always display
     * the parsed value back to the user to make sure we understood his input
     * correctly.
     */
    parseValue: function (valueString) {
        if (!valueString) return Bitcoin.BigInteger.ZERO;

        valueString = ''+valueString;

        if (!/^[\d.]+$/.test(valueString)) {
            return Bitcoin.BigInteger.ZERO;
        }

        // TODO: Detect other number formats (e.g. comma as decimal separator)
        var valueComp = valueString.split('.');
        var integralPart = valueComp[0];
        var fractionalPart = valueComp[1] || "0";

        fractionalPart = fractionalPart.length > 8 ? fractionalPart.substr(0, 8) : fractionalPart;

        while (fractionalPart.length < 8) fractionalPart += "0";

        fractionalPart = fractionalPart.replace(/^0+/g, '');
        var value = new Bitcoin.BigInteger(integralPart);
        value = value.multiply(new Bitcoin.BigInteger('100000000'));
        value = value.add(new Bitcoin.BigInteger(fractionalPart));
        return value;
    },

    /**
     * Calculate RIPEMD160(SHA256(data)).
     *
     * Takes an arbitrary byte array as inputs and returns the hash as a byte
     * array.
     */
    sha256ripe160: function (data) {
        return Bitcoin.CryptoJS.RIPEMD160(Bitcoin.CryptoJS.SHA256(data));
    }
};

if (self.angular) {  // not in WebWorkers
    var $q = angular.injector(['ng']).get('$q');
}

if (self.cordova && cordova.platformId == 'ios') {

    function cordovaReady(fn) {
        var queue = [];

        var impl = function () {
          queue.push([this, Array.prototype.slice.call(arguments)]);
        };

        document.addEventListener('deviceready', function () {
          queue.forEach(function (args) {
            fn.apply(args[0], args[1]);
          });
          impl = fn;
        }, false);

        return function () {
          return impl.apply(this, arguments);
        };
    };

    Bitcoin.bitcoin.HDNode.fromSeedHex = cordovaReady(function(seed_hex, network) {
        var deferred = $q.defer();
        cordova.exec(function(param) {
            var wallet = new Bitcoin.bitcoin.HDNode(
                new Bitcoin.bitcoin.ECPair(
                    Bitcoin.BigInteger.fromBuffer(
                        new Bitcoin.Buffer.Buffer(param[0], 'hex')
                    ),
                    null,
                    {compressed: true, network: network}
                ),
                new Bitcoin.Buffer.Buffer(param[2], 'hex')
            );
            // wallet.pub = new Bitcoin.ECPubKey(param[1], true);
            deferred.resolve(wallet);
        }, function(fail) {
            console.log('BIP32.seedToKey failed: ' + fail)
            deferred.reject(fail);
        }, "BIP32", "seedToKey", [seed_hex]);
        return deferred.promise;
    });

    Bitcoin.bitcoin.HDNode.prototype.derive = function(i) {
        var deferred = $q.defer();
        var usePriv = i >= Bitcoin.bitcoin.HDNode.HIGHEST_BIT

        if (usePriv) {
            i -= Bitcoin.bitcoin.HDNode.HIGHEST_BIT;
        }

        var that = this;
        var orig_network = this.network;
        this.network = 'mainnet';  // our BIP32 for iOS doesn't support testnet
        cordova.exec(function(param) {
            var ec_pair;
            if (that.keyPair.d) {
                ec_pair = new Bitcoin.bitcoin.ECPair(
                    Bitcoin.BigInteger.fromBuffer(
                        new Bitcoin.Buffer.Buffer(param[0], 'hex')
                    ),
                    null,
                    {compressed: true, network: that.network}
                );
            } else {
                ec_pair = Bitcoin.bitcoin.ECPair.fromPublicKeyBuffer(
                    new Bitcoin.Buffer.Buffer(param[1]),
                    that.network
                )
            }
            var hd = new Bitcoin.bitcoin.HDNode(
                ec_pair,
                new Bitcoin.Buffer.Buffer(param[2], 'hex')
            );
            hd.parentFingerprint = that.getFingerprint();
            hd.depth = that.depth + 1;
            hd.index = i;
            deferred.resolve(hd);
        }, function(fail) {
            console.log('BIP32.derive failed: ' + fail)
            deferred.reject(fail);
        }, "BIP32", "derive", [
            Bitcoin.bs58check.decode(this.toBase58()).toString("hex"),
            parseInt(i), usePriv ? "true" : "false"
        ]);
        this.network = orig_network;

        return deferred.promise;
    }

    Bitcoin.bitcoin.ECPair.prototype.sign = function(hash) {
        var deferred = $q.defer();
        cordova.exec(function(der) {
            deferred.resolve(Bitcoin.bitcoin.ECSignature.fromDER(
                new Bitcoin.Buffer.Buffer(der, 'hex')
            ));
        }, function(fail) {
            console.log('ecdsa.sign failed: ' + fail)
            deferred.reject(fail);
        }, "ECDSA", "sign", [
            this.toWIF(),
            new Bitcoin.Buffer.Buffer(hash).toString('hex')
        ]);
        return deferred.promise;
    }
} else {
    if (!self.cordova && self.angular) {
        angular.element(document).ready(function() {
            var ready = false;
            var script = document.createElement('script')
            script.type = 'text/javascript';
            if (cur_net.isAlpha) {
                script.src = '/static/js/secp256k1-alpha.js';
            } else {
                script.src = '/static/js/secp256k1.js';
            }
            script.onload = script.onreadystatechange = function () {
                if (!ready && (!this.readyState || this.readyState == 'complete')) {
                    ready = true;
                    Module.secp256k1ctx = Module._secp256k1_context_create(3);
                    if (cur_net.isAlpha) {
                        Module._secp256k1_pedersen_context_initialize(Module.secp256k1ctx);
                        Module._secp256k1_rangeproof_context_initialize(Module.secp256k1ctx);
                    }
                    var randArr = new Uint8Array(32);
                    crypto.getRandomValues(randArr);
                    if (!Module._secp256k1_context_randomize(Module.secp256k1ctx, randArr)) {
                        throw new Error("Couldn't initialize library, randomized failed");
                    }
                }
            };
            var tag = document.getElementsByTagName('script')[0];
            tag.parentNode.insertBefore(script, tag);
        });

        no_secp256k1_getPub = Bitcoin.bitcoin.ECPair.prototype.getPublicKeyBuffer;
        Bitcoin.bitcoin.ECPair.prototype.getPublicKeyBuffer = function() {
            // TODO: implementation for alpha's libsecp256k1
            if (self.Module === undefined || !this.d || cur_net.isAlpha) {
                // in case it's called before module finishes initialisation,
                // or in case of pubkey-only ECPair
                return no_secp256k1_getPub.bind(this)();
            }
            var compressed = this.compressed;

            var out = Module._malloc(128);
            var out_s = Module._malloc(4);
            var secexp = Module._malloc(32);
            var start = this.d.toByteArray().length - 32;
            if (start >= 0) {  // remove excess zeroes
                var slice = this.d.toByteArray().slice(start);
            } else {  // add missing zeroes
                var slice = this.d.toByteArray();
                while (slice.length < 32) slice.unshift(0);
            }
            writeArrayToMemory(slice, secexp);
            setValue(out_s, 128, 'i32');

            Module._secp256k1_ec_pubkey_create(Module.secp256k1ctx, out, out_s, secexp, compressed ? 1 : 0);

            var ret = [];
            for (var i = 0; i < getValue(out_s, 'i32'); ++i) {
                ret[i] = getValue(out+i, 'i8') & 0xff;
            }

            return new Bitcoin.Buffer.Buffer(ret);
        };
    }
    if (self.Worker && !self.GAIT_IN_WORKER) {
        (function() {
            var worker = new Worker(BASE_URL+"/static/js/bitcoinjs_util_worker.js"), callId = 0,
                cbs = {};

            worker.onmessage = function(message) {
                cbs[message.data.callId](message.data.result);
                delete cbs[message.data.callId];
            }

            Bitcoin.bitcoin.HDNode.prototype.derive = function(i) {
                var deferred = $q.defer(), that = this;
                cbs[++callId] = function(derived) {
                    deferred.resolve(
                        Bitcoin.bitcoin.HDNode.fromBase58(derived, that.keyPair.network)
                    );
                };
                worker.postMessage({
                    isAlpha: cur_net.isAlpha,
                    func: 'derive',
                    data: {wallet: this.toBase58(), i: i},
                    callId: callId
                })
                return deferred.promise;
            }

            Bitcoin.bitcoin.ECPair.prototype.sign = function(hash) {
                var deferred = $q.defer();
                if (cur_net.isAlpha) {
                    cbs[++callId] = deferred.resolve;
                } else {
                    cbs[++callId] = function(der) {
                        deferred.resolve(Bitcoin.bitcoin.ECSignature.fromDER(der));
                    };
                }
                worker.postMessage({
                    isAlpha: cur_net.isAlpha,
                    func: 'sign',
                    data: {key: this.toWIF(), hash: hash},
                    callId: callId
                })
                return deferred.promise;
            }
        })();
    }
}

Bitcoin.bitcoin.HDNode.prototype.subpath = function(path_hex) {
    var key = $q.when(this);
    var path_bytes = new Bitcoin.Buffer.Buffer(path_hex, 'hex');
    for (var i = 0; i < 32; i++) {
        key = key.then(function(key) {
            var dk = key.derive(+Bitcoin.BigInteger.fromBuffer(path_bytes.slice(0, 2)));;
            path_bytes = path_bytes.slice(2);
            return dk;
        });
    }
    return key;
}
Bitcoin.bitcoin.HDNode.prototype.subpath_for_login = function(path_hex) {
    // derive private key for signing the challenge, using 8 bytes instead of 64
    var key = $q.when(this);
    if (path_hex.length == 17 && path_hex[0] == '0') {  // new version with leading 0
        path_hex = path_hex.slice(1);
        var path_bytes = new Bitcoin.Buffer.Buffer(path_hex, 'hex');
        for (var i = 0; i < 2; i++) {
            key = key.then(function(key) {
                var dk = key.derive(+Bitcoin.BigInteger.fromBuffer(path_bytes.slice(0, 4)));
                path_bytes = path_bytes.slice(4);
                return dk;
            });
        }
    } else {
        var path_bytes = new Bitcoin.Buffer.Buffer(path_hex, 'hex');
        for (var i = 0; i < 4; i++) {
            key = key.then(function(key) {
                var dk = key.derive(+Bitcoin.BigInteger.fromBuffer(path_bytes.slice(0, 2)));
                path_bytes = path_bytes.slice(2);
                return dk;
            });
        }
    }
    return key;
}

if (self.scrypt_module_factory) {  // WebWorkers only
    var scrypt = scrypt_module_factory();
}

Bitcoin.scrypt = function(passwd, salt, N, r, p, dkLen) {
    if (typeof passwd == 'string') {
        passwd = scrypt.encode_utf8(passwd);
    }
    var ret_arr = scrypt.crypto_scrypt(new Uint8Array(passwd), new Uint8Array(salt), N, r, p, dkLen);
    var ret = [];
    for (var i = 0; i < ret_arr.length; i++) ret.push(ret_arr[i]);
    return new Bitcoin.Buffer.Buffer(ret);
}

Bitcoin.bitcoin.Transaction.prototype.cloneTransactionForSignature =
  function (connectedScript, inIndex, hashType)
{
  var txTmp = this.clone()

  // In case concatenating two scripts ends up with two codeseparators,
  // or an extra one at the end, this prevents all those possible
  // incompatibilities.
  /*scriptCode = scriptCode.filter(function (val) {
    return val !== OP_CODESEPARATOR
    });*/

  // Blank out other inputs' signatures
  txTmp.ins.forEach(function(txin) {
    txin.script = new Bitcoin.Buffer.Buffer()
  })

  txTmp.ins[inIndex].script = connectedScript

  // Blank out some of the outputs
  /*if ((hashType & 0x1f) == SIGHASH_NONE) {
    txTmp.outs = []

    // Let the others update at will
    txTmp.ins.forEach(function(txin, i) {
      if (i != inIndex) {
        txTmp.ins[i].sequence = 0
      }
    })

  } else if ((hashType & 0x1f) == SIGHASH_SINGLE) {
    // TODO: Implement
  }

  // Blank out other inputs completely, not recommended for open transactions
  if (hashType & SIGHASH_ANYONECANPAY) {
    txTmp.ins = [txTmp.ins[inIndex]]
  }*/

  return txTmp
}

Bitcoin.bitcoin.Transaction.prototype.serializeOutputs = function () {
  var parts = [];

  parts.push(Bitcoin.convert.numToVarInt(this.outs.length))

  this.outs.forEach(function(txout) {
    var valueBuf = new Buffer(8);
    Bitcoin.bitcoin.bufferutils.writeUInt64LE(valueBuf, txout.value, 0);
    parts.push(valueBuf);
    parts.push(Bitcoin.bitcoin.bufferutils.varIntBuffer(txout.script.length));
    parts.push(txout.script);
  })

  return Bitcoin.Buffer.Buffer.concat(parts);
}