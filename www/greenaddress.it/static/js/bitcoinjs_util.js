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

    Bitcoin.HDWallet.fromSeedHex = cordovaReady(function(seed_hex, network) {
        var deferred = $q.defer();
        cordova.exec(function(param) {
            var wallet = new Bitcoin.HDWallet();
            wallet.priv = new Bitcoin.ECKey(param[0], true);
            wallet.pub = new Bitcoin.ECPubKey(param[1], true);
            wallet.chaincode = Bitcoin.convert.hexToBytes(param[2]);
            wallet.network = network;
            wallet.depth = 0;
            wallet.index = 0;
            deferred.resolve(wallet);
        }, function(fail) {
            console.log('BIP32.seedToKey failed: ' + fail)
            deferred.reject(fail);
        }, "BIP32", "seedToKey", [seed_hex]);
        return deferred.promise;
    });

    Bitcoin.HDWallet.prototype.derive = function(i) {
        var deferred = $q.defer();
        var usePriv = i >= Bitcoin.HDWallet.HIGHEST_BIT

        if (usePriv) {
            i -= Bitcoin.HDWallet.HIGHEST_BIT;
        }

        var that = this;
        var orig_network = this.network;
        this.network = 'mainnet';  // our BIP32 for iOS doesn't support testnet
        cordova.exec(function(param) {
            var hd = new Bitcoin.HDWallet()
            hd.network = that.network

            if (that.priv)
                hd.priv = new Bitcoin.ECKey(param[0], true);
            hd.pub = new Bitcoin.ECPubKey(param[1], true);
            hd.chaincode = Bitcoin.convert.hexToBytes(param[2]);

            hd.parentFingerprint = that.getFingerprint();
            hd.depth = that.depth + 1;
            hd.index = i;
            deferred.resolve(hd);
        }, function(fail) {
            console.log('BIP32.derive failed: ' + fail)
            deferred.reject(fail);
        }, "BIP32", "derive", [this.toHex(!!this.priv), parseInt(i), usePriv ? "true" : "false"]);
        this.network = orig_network;

        return deferred.promise;
    }

    Bitcoin.ECKey.prototype.sign = function(hash) {
        var deferred = $q.defer();
        cordova.exec(function(param) {
            deferred.resolve(Bitcoin.convert.hexToBytes(param));
        }, function(fail) {
            console.log('ecdsa.sign failed: ' + fail)
            deferred.reject(fail);
        }, "ECDSA", "sign", [this.toWif(), Bitcoin.convert.bytesToHex(hash)]);
        return deferred.promise;
    }
} else {
    if (!self.cordova && self.angular) {
        angular.element(document).ready(function() {
            var ready = false;
            var script = document.createElement('script')
            script.type = 'text/javascript';
            script.src = '/static/js/secp256k1.js';
            script.onload = script.onreadystatechange = function () {
                if (!ready && (!this.readyState || this.readyState == 'complete')) {
                    ready = true;
                    Module._secp256k1_start(3);
                }
            };
            var tag = document.getElementsByTagName('script')[0];
            tag.parentNode.insertBefore(script, tag);
        });

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

            Module._secp256k1_ec_pubkey_create(out, out_s, secexp, compressed ? 1 : 0);

            var ret = [];
            for (var i = 0; i < getValue(out_s, 'i32'); ++i) {
                ret[i] = getValue(out+i, 'i8') & 0xff;
            }

            return Bitcoin.ECPubKey(ret, compressed)
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

            Bitcoin.HDWallet.prototype.derive = function(i) {
                var deferred = $q.defer(), that = this;
                cbs[++callId] = function(derived) {
                    deferred.resolve(Bitcoin.HDWallet.fromBase58(derived));
                };
                worker.postMessage({
                    func: 'derive',
                    data: {wallet: this.toBase58(this.priv), i: i},
                    callId: callId
                })
                return deferred.promise;
            }

            Bitcoin.ECKey.prototype.sign = function(hash) {
                var deferred = $q.defer();
                cbs[++callId] = deferred.resolve;
                worker.postMessage({
                    func: 'sign',
                    data: {key: this.toWif(), hash: hash},
                    callId: callId
                })
                return deferred.promise;
            }
        })();
    }
}

Bitcoin.HDWallet.prototype.subpath = function(path_hex) {
    var key = $q.when(this);
    var path_bytes = Bitcoin.convert.hexToBytes(path_hex);
    for (var i = 0; i < 32; i++) {
        key = key.then(function(key) {
            var dk = key.derive(+Bitcoin.BigInteger.fromByteArrayUnsigned(path_bytes.slice(0, 2)));;
            path_bytes.shift(); path_bytes.shift();
            return dk;
        });
    }
    return key;
}
Bitcoin.HDWallet.prototype.subpath_for_login = function(path_hex) {
    // derive private key for signing the challenge, using 8 bytes instead of 64
    var key = $q.when(this);
    if (path_hex.length == 17 && path_hex[0] == '0') {  // new version with leading 0
        path_hex = path_hex.slice(1);
        var path_bytes = Bitcoin.convert.hexToBytes(path_hex);
        for (var i = 0; i < 2; i++) {
            key = key.then(function(key) {
                var dk = key.derive(+Bitcoin.BigInteger.fromByteArrayUnsigned(path_bytes.slice(0, 4)));
                path_bytes.shift(); path_bytes.shift(); path_bytes.shift(); path_bytes.shift();
                return dk;
            });
        }
    } else {
        var path_bytes = Bitcoin.convert.hexToBytes(path_hex);
        for (var i = 0; i < 4; i++) {
            key = key.then(function(key) {
                var dk = key.derive(+Bitcoin.BigInteger.fromByteArrayUnsigned(path_bytes.slice(0, 2)));
                path_bytes.shift(); path_bytes.shift();
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
    return ret;
}



// from https://github.com/BitGo/bitcoinjs-lib/blob/master/src/bip38.js

/**
 * Private key encoded per BIP-38 (password encrypted, checksum,  base58)
 */
Bitcoin.ECKey.prototype.getEncryptedFormat = function (passphrase, network) {
    return Bitcoin.BIP38.encode(this, passphrase, network);
}

Bitcoin.ECKey.decodeEncryptedFormat = function (base58Encrypted, passphrase, cur_net) {
    return Bitcoin.BIP38.decode(base58Encrypted, passphrase, cur_net);
}

Bitcoin.CryptoJS.AES.decryptCompat = function(bytes, key, opts) {
    return Bitcoin.convert.wordArrayToBytes(
                Bitcoin.CryptoJS.AES.decrypt(
                    Bitcoin.CryptoJS.lib.CipherParams.create({ciphertext:
                        Bitcoin.convert.bytesToWordArray(bytes)}),
                    Bitcoin.convert.bytesToWordArray(key),
                    opts));
}

Bitcoin.CryptoJS.AES.encryptCompat = function(bytes, key, opts) {
    return Bitcoin.convert.wordArrayToBytes(Bitcoin.CryptoJS.AES.encrypt(
        Bitcoin.convert.bytesToWordArray(bytes),
        Bitcoin.convert.bytesToWordArray(key),
        opts).ciphertext);
}

Bitcoin.ECKey.prototype.getPrivateKeyByteArray = function () {
    // Get a copy of private key as a byte array
    var bytes = this.priv.toByteArrayUnsigned();
    // zero pad if private key is less than 32 bytes
    while (bytes.length < 32) bytes.unshift(0x00);
    return bytes;
};

// from https://github.com/jasondavies/jsbn/pull/1
function curveFpDecompressPoint(curve, yOdd, X) {
  if(curve.q.mod(Bitcoin.BigInteger.valueOf(4)).equals(Bitcoin.BigInteger.valueOf(3))) {
    // y^2 = x^3 + ax^2 + b, so we need to perform sqrt to recover y
    var ySquared = X.multiply(X.square().add(curve.a)).add(curve.b);

    // sqrt(a) = a^((q-1)/4) if q = 3 mod 4
    var Y = ySquared.x.modPow(curve.q.add(Bitcoin.BigInteger.ONE).divide(Bitcoin.BigInteger.valueOf(4)), curve.q);

    if(Y.testBit(0) !== yOdd) {
      Y = curve.q.subtract(Y);
    }

    return new Bitcoin.ECPointFp(curve, X, curve.fromBigInteger(Y));
  } else {
    throw new Error("point decompression only implements sqrt for q = 3 mod 4");
  }
};


// for now, work with hex strings because they're easier in JS
function curveFpDecodePointHex(curve, s) {
    switch(parseInt(s.substr(0,2), 16)) { // first byte
    case 0:
        return curve.infinity;
    case 2:
        return curveFpDecompressPoint(curve, false, curve.fromBigInteger(new Bitcoin.BigInteger(s.substr(2), 16)));
    case 3:
        return curveFpDecompressPoint(curve, true, curve.fromBigInteger(new Bitcoin.BigInteger(s.substr(2), 16)));
    case 4:
    case 6:
    case 7:
        var len = (s.length - 2) / 2;
        var xHex = s.substr(2, len);
        var yHex = s.substr(len+2, len);

        return new Bitcoin.ECPointFp(curve,
                     curve.fromBigInteger(new Bitcoin.BigInteger(xHex, 16)),
                     curve.fromBigInteger(new Bitcoin.BigInteger(yHex, 16)));

    default: // unsupported
        return null;
    }
}

Bitcoin.BIP38 = (function () {

  function sha256(buf) {
    if (typeof buf == "string") {
        buf = Bitcoin.CryptoJS.enc.Utf8.parse(buf);
    } else {
        buf = Bitcoin.convert.bytesToWordArray(buf);
    }
    var hash = Bitcoin.CryptoJS.SHA256(buf);
    hash = Bitcoin.convert.wordArrayToBytes(hash);
    return hash;
  }

  var BIP38 = function() {};


  /**
   * Standard bitcoin curve - secp256k1
   */
  var ecparams = Bitcoin.getSECCurveByName("secp256k1");

  /**
   * Random number generator
   */
  var rng = Bitcoin.SecureRandom;

  /**
   * Default parameters for scrypt key derivation
   *  -> N: cpu cost
   *  -> r: memory cost
   *  -> p: parallelization cost
   */
  var scryptParams = {
    passphrase: { N: 16384, r: 8, p: 8 },        // Way too slow (especially on IE), but recommended values
    passpoint: { N: 1024, r: 1, p: 1 }
  };

  /**
   * Default parameters for AES
   */
  var AES_opts = {mode: Bitcoin.CryptoJS.mode.ECB,
                  padding: Bitcoin.CryptoJS.pad.NoPadding};



  /**
   * Private key encoded per BIP-38 (password encrypted, checksum,  base58)
   * @author scintill
   */
  BIP38.encode = function (eckey, passphrase, cur_net) {
    var privKeyBytes = eckey.getPrivateKeyByteArray();
    var address = eckey.getAddress(Bitcoin.network[cur_net].addressVersion).toString();

    // compute sha256(sha256(address)) and take first 4 bytes
    var salt = sha256(sha256(address)).slice(0, 4);

    // derive key using scrypt
    var derivedBytes = Bitcoin.scrypt(passphrase, salt, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 64);
    for(var i = 0; i < 32; ++i) {
      privKeyBytes[i] ^= derivedBytes[i];
    }

    // 0x01 0x42 + flagbyte + salt + encryptedhalf1 + encryptedhalf2
    var flagByte = eckey.compressed ? 0xe0 : 0xc0;
    var encryptedKey = [ 0x01, 0x42, flagByte ].concat(salt);

    var encryptedKey = encryptedKey.concat(Bitcoin.CryptoJS.AES.encryptCompat(privKeyBytes, derivedBytes.slice(32), AES_opts));

    encryptedKey = encryptedKey.concat(sha256(sha256(encryptedKey)).slice(0,4));

    return Bitcoin.base58.encode(encryptedKey);
  }

  /**
   * Parse a wallet import format private key contained in a string.
   * @author scintill
   */
  BIP38.decode = function (base58Encrypted, passphrase, cur_net) {
    var hex_uint8, hex;
    try {
      hex_uint8 = Bitcoin.base58.decode(base58Encrypted);
      hex = [];
      for (var i = 0; i < hex_uint8.length; i++) hex.push(hex_uint8[i]);
    } catch (e) {
      throw new Error("Invalid BIP38-encrypted private key. Unable to decode base58.");
    }

    if (hex.length != 43) {
      throw new Error("Invalid BIP38-encrypted private key. Length of key in hex format is not 43 characters in length.");
    } else if (hex[0] != 0x01) {
      throw new Error("Invalid BIP38-encrypted private key. First byte is not 0x01.");
    }

    var expChecksum = hex.slice(-4);
    hex = hex.slice(0, -4);

    var checksum = sha256(sha256(hex));
    if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
      throw new Error("Invalid BIP38-encrypted private key. Checksum failed.");
    }

    var isCompPoint = false;
    var isECMult = false;
    var hasLotSeq = false;
    if (hex[1] == 0x42) {
      if (hex[2] == 0xe0) {
        isCompPoint = true;
      } else if (hex[2] != 0xc0) {
        throw new Error("Invalid BIP38-encrypted private key. Second byte should be 0xc0.");
      }
    } else if (hex[1] == 0x43) {
      isECMult = true;
      isCompPoint = (hex[2] & 0x20) != 0;
      hasLotSeq = (hex[2] & 0x04) != 0;
      if ((hex[2] & 0x24) != hex[2]) {
        throw new Error("Invalid BIP38-encrypted private key. Unknown validation error.");
      }
    } else {
      throw new Error("Invalid BIP38-encrypted private key. Unknown validation error.");
    }

    var decrypted;
    var verifyHashAndReturn = function() {
      var tmpkey = new Bitcoin.ECKey(decrypted, isCompPoint);

      var address = tmpkey.getAddress(Bitcoin.network[cur_net].addressVersion);
      checksum = sha256(sha256(address.toString()));

      if (checksum[0] != hex[3] || checksum[1] != hex[4] || checksum[2] != hex[5] || checksum[3] != hex[6]) {
        throw new Error("Invalid BIP38-encrypted private key. Hash could not be verified.");
      }

      return tmpkey;
    };

    if (!isECMult) {
      var addresshash = hex.slice(3, 7);
      var derivedBytes = Bitcoin.scrypt(passphrase, addresshash, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 64);
      var k = derivedBytes.slice(32, 32+32);
      decrypted = Bitcoin.CryptoJS.AES.decryptCompat(hex.slice(7, 7+32), k, AES_opts);
      for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];
      return verifyHashAndReturn();
    } else {
      var ownerentropy = hex.slice(7, 7+8);
      var ownersalt = !hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4);
      var prefactorA = Bitcoin.scrypt(passphrase, ownersalt, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 32);
      var passfactor;
      if (!hasLotSeq) {
        passfactor = prefactorA;
      } else {
        var prefactorB = prefactorA.concat(ownerentropy);
        passfactor = sha256(sha256(prefactorB));
      }
      var kp = new Bitcoin.ECKey(passfactor);
      kp.compressed = true;
      var passpoint = kp.getPub().toBytes();

      var encryptedPart2 = hex.slice(23, 23+16);

      var addressHashPlusOnwerEntropy = hex.slice(3, 3+12);
      var derived = Bitcoin.scrypt(passpoint, addressHashPlusOnwerEntropy, scryptParams.passpoint.N, scryptParams.passpoint.r, scryptParams.passpoint.p, 64);
      var k = derived.slice(32);

      var unencryptedPart2 = Bitcoin.CryptoJS.AES.decryptCompat(encryptedPart2, k, AES_opts);
      for (var i = 0; i < 16; i++) { unencryptedPart2[i] ^= derived[i+16]; }

      var encryptedpart1 = hex.slice(15, 15+8).concat(unencryptedPart2.slice(0, 0+8));
      var unencryptedpart1 = Bitcoin.CryptoJS.AES.decryptCompat(encryptedpart1, k, AES_opts);
      for (var i = 0; i < 16; i++) { unencryptedpart1[i] ^= derived[i]; }

      var seedb = unencryptedpart1.slice(0, 0+16).concat(unencryptedPart2.slice(8, 8+8));

      var factorb = sha256(sha256(seedb));

      var privateKey = Bitcoin.BigInteger.fromByteArrayUnsigned(passfactor).multiply(Bitcoin.BigInteger.fromByteArrayUnsigned(factorb)).remainder(ecparams.getN());

      decrypted = privateKey.toByteArrayUnsigned();
      return verifyHashAndReturn();
    }
  }

  /**
   * Generates an intermediate point based on a password which can later be used
   * to directly generate new BIP38-encrypted private keys without actually knowing
   * the password.
   * @author Zeilap
   */
  BIP38.generateIntermediate = function(passphrase, lotNum, sequenceNum) {
    var noNumbers = lotNum == null || sequenceNum == null;
    var ownerEntropy, ownerSalt;

    if(noNumbers) {
      ownerSalt = ownerEntropy = rng(8, { array: true });
    } else {
      // 1) generate 4 random bytes
      var ownerSalt = rng(4, { array: true });

      // 2)  Encode the lot and sequence numbers as a 4 byte quantity (big-endian):
      // lotnumber * 4096 + sequencenumber. Call these four bytes lotsequence.
      var lotSequence = new Bitcoin.BigInteger((4096*lotNum + sequenceNum).toString()).toByteArrayUnsigned();

      // 3) Concatenate ownersalt + lotsequence and call this ownerentropy.
      var ownerEntropy = ownerSalt.concat(lotSequence);
    }

    // 4) Derive a key from the passphrase using scrypt
    var prefactor = Bitcoin.scrypt(passphrase, ownerSalt, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 32);


    // Take SHA256(SHA256(prefactor + ownerentropy)) and call this passfactor
    var passfactorBytes = noNumbers ? prefactor : sha256(sha256(prefactor.concat(ownerEntropy)));
    var passfactor = Bitcoin.BigInteger.fromByteArrayUnsigned(passfactorBytes);

    // 5) Compute the elliptic curve point G * passfactor, and convert the result to compressed notation (33 bytes)
    var passpoint = ecparams.getG().multiply(passfactor).getEncoded(1);

    // 6) Convey ownersalt and passpoint to the party generating the keys, along with a checksum to ensure integrity.
    // magic bytes "2C E9 B3 E1 FF 39 E2 51" followed by ownerentropy, and then passpoint
    var magicBytes = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51];
    if(noNumbers) magicBytes[7] = 0x53;

    var intermediatePreChecksum = magicBytes.concat(ownerEntropy).concat(passpoint);
    var intermediateBytes = intermediatePreChecksum.concat(sha256(sha256(intermediatePreChecksum)).slice(0,4));
    var intermediate = Bitcoin.base58.encode(intermediateBytes);

    return intermediate;
  };

  /**
   * Creates new private key using an intermediate EC point.
   */
  BIP38.newAddressFromIntermediate = function(intermediate, compressed) {
    // validate intermediate code
    if (!BIP38.verifyIntermediate(intermediate)) {
      throw new Error("Invalid intermediate passphrase string");
    }

    // decode IPS
    var intermediateBytes_uint8 = Bitcoin.base58.decode(intermediate);
    var intermediateBytes = [];
    for (var i = 0; i < intermediateBytes_uint8.length; i++) intermediateBytes.push(intermediateBytes_uint8[i]);
    var noNumbers = (intermediateBytes[7] === 0x53);
    var ownerEntropy = intermediateBytes.slice(8, 8+8);
    var passpoint = intermediateBytes.slice(16, 16+33);

    // 1) Set flagbyte.
    // set bit 0x20 for compressed key
    // set bit 0x04 if ownerentropy contains a value for lotsequence
    var flagByte = (compressed? 0x20 : 0x00) | (noNumbers? 0x00 : 0x04);

    // 2) Generate 24 random bytes, call this seedb.
    var seedB = rng(24, { array: true });

    // Take SHA256(SHA256(seedb)) to yield 32 bytes, call this factorb.
    var factorB = sha256(sha256(seedB));

    // 3) ECMultiply passpoint by factorb. Use the resulting EC point as a public key and hash it into a Bitcoin
    // address using either compressed or uncompressed public key methodology (specify which methodology is used
    // inside flagbyte). This is the generated Bitcoin address, call it generatedAddress.
    var ec = ecparams.getCurve();
    var generatedPoint = curveFpDecodePointHex(ec, Bitcoin.convert.bytesToHex(passpoint));
    var generatedBytes = generatedPoint.multiply(Bitcoin.BigInteger.fromByteArrayUnsigned(factorB)).getEncoded(compressed);
    var generatedAddress = new Bitcoin.Address(Bitcoin.convert.wordArrayToBytes(Bitcoin.Util.sha256ripe160(
        Bitcoin.convert.bytesToWordArray(generatedBytes))));

    // 4) Take the first four bytes of SHA256(SHA256(generatedaddress)) and call it addresshash.
    var addressHash = sha256(sha256(generatedAddress.toString())).slice(0,4);

    // 5) Now we will encrypt seedb. Derive a second key from passpoint using scrypt
    var derivedBytes = Bitcoin.scrypt(passpoint, addressHash.concat(ownerEntropy), scryptParams.passpoint.N, scryptParams.passpoint.r, scryptParams.passpoint.p, 64);

    // 6) Do AES256Encrypt(seedb[0...15]] xor derivedhalf1[0...15], derivedhalf2), call the 16-byte result encryptedpart1
    for(var i = 0; i < 16; ++i) {
      seedB[i] ^= derivedBytes[i];
    }
    var encryptedPart1 = Bitcoin.CryptoJS.AES.encryptCompat(seedB.slice(0,16), derivedBytes.slice(32), AES_opts);

    // 7) Do AES256Encrypt((encryptedpart1[8...15] + seedb[16...23]) xor derivedhalf1[16...31], derivedhalf2), call the 16-byte result encryptedseedb.
    var message2 = encryptedPart1.slice(8, 8+8).concat(seedB.slice(16, 16+8));
    for(var i = 0; i < 16; ++i) {
      message2[i] ^= derivedBytes[i+16];
    }
    var encryptedSeedB = Bitcoin.CryptoJS.AES.encryptCompat(message2, derivedBytes.slice(32), AES_opts);

    // 0x01 0x43 + flagbyte + addresshash + ownerentropy + encryptedpart1[0...7] + encryptedPart2
    var encryptedKey = [ 0x01, 0x43, flagByte ].concat(addressHash).concat(ownerEntropy).concat(encryptedPart1.slice(0,8)).concat(encryptedSeedB);
    // base58check encode
    encryptedKey = encryptedKey.concat(sha256(sha256(encryptedKey)).slice(0,4));

    // Generate confirmation code for the new address
    var confirmation = newAddressConfirmation(addressHash, factorB, derivedBytes, flagByte, ownerEntropy);
    return { address: generatedAddress,
             bip38PrivateKey: Bitcoin.base58.encode(encryptedKey),
             confirmation: confirmation };
  };

  /**
   * Generates a confirmation code for a key/address generated using an intermediate
   * ec point (see BIP38.newAddressFromIntermediate).  This certifies that the address
   * truly corresponds to the password from which the intermediate ec point was derived
   * (see BIP38.verifyNewAddressConfirmation).
   */
  var newAddressConfirmation = function(addressHash, factorB, derivedBytes, flagByte, ownerEntropy) {
    // 1) ECMultiply factorb by G, call the result pointb. The result is 33 bytes.
    var pointb = ecparams.getG().multiply(Bitcoin.BigInteger.fromByteArrayUnsigned(factorB)).getEncoded(1);

    // 2) he first byte is 0x02 or 0x03. XOR it by (derivedhalf2[31] & 0x01), call the resulting byte pointbprefix.
    var pointbprefix = pointb[0] ^ (derivedBytes[63] & 0x01);

    // 3) Do AES256Encrypt(pointb[1...16] xor derivedhalf1[0...15], derivedhalf2) and call the result pointbx1.
    for(var i = 0; i < 16; ++i) {
      pointb[i + 1] ^= derivedBytes[i];
    }
    var pointbx1 = Bitcoin.CryptoJS.AES.encryptCompat(pointb.slice(1,17), derivedBytes.slice(32), AES_opts);

    // 4) Do AES256Encrypt(pointb[17...32] xor derivedhalf1[16...31], derivedhalf2) and call the result pointbx2.
    for(var i = 16; i < 32; ++i) {
      pointb[i + 1] ^= derivedBytes[i];
    }
    var pointbx2 = Bitcoin.CryptoJS.AES.encryptCompat(pointb.slice(17,33), derivedBytes.slice(32), AES_opts);

    var encryptedpointb = [ pointbprefix ].concat(pointbx1).concat(pointbx2);

    var confirmationPreChecksum =
      [ 0x64, 0x3B, 0xF6, 0xA8, 0x9A, flagByte ]
        .concat(addressHash)
        .concat(ownerEntropy)
        .concat(encryptedpointb);
    var confirmationBytes = confirmationPreChecksum.concat(sha256(sha256(confirmationPreChecksum)).slice(0,4));
    var confirmation = Bitcoin.base58.encode(confirmationBytes);

    return confirmation;
  };

  /**
   * Certifies that the given address was generated using an intermediate ec point derived
   * from the given password (see BIP38.newAddressFromIntermediate).
   */
  BIP38.verifyNewAddressConfirmation = function(expectedAddressStr, confirmation, passphrase) {
    var confirmationResults = BIP38.verifyConfirmation(confirmation, passphrase);
    return (confirmationResults.address == expectedAddressStr);
  };

  /**
   * Certifies that the given BIP38 confirmation code matches the password and
   * returns the address the confirmation corresponds to (see BIP38.newAddressFromIntermediate).
   */
  BIP38.verifyConfirmation = function(confirmation, passphrase) {
    var bytes_uint8 = Bitcoin.base58.decode(confirmation);
    var bytes = [];
    for (var i = 0; i < bytes_uint8.length; i++) bytes.push(bytes_uint8[i]);

    // Get the flag byte (tells us whether address compression is used and whether lot/sequence values are present).
    var flagByte = bytes[5];

    // Get the address hash.
    var addressHash = bytes.slice(6, 10);

    // Get the owner entropy (tells us the lot/sequence values when applicable).
    var ownerEntropy = bytes.slice(10, 18);

    // Get encryptedpointb
    var encryptedpointb = bytes.slice(18, 51);

    var compressed = (flagByte & 0x20) == 0x20;
    var lotSequencePresent = (flagByte & 0x04) == 0x04;
    var ownerSalt = ownerEntropy.slice(0, lotSequencePresent ? 4 : 8)

    var prefactor = Bitcoin.scrypt(passphrase, ownerSalt, scryptParams.passphrase.N, scryptParams.passphrase.r, scryptParams.passphrase.p, 32);

    // Take SHA256(SHA256(prefactor + ownerentropy)) and call this passfactor
    var passfactorBytes = !lotSequencePresent? prefactor : sha256(sha256(prefactor.concat(ownerEntropy)));
    var passfactor = Bitcoin.BigInteger.fromByteArrayUnsigned(passfactorBytes);

    var passpoint = ecparams.getG().multiply(passfactor).getEncoded(1);

    var addresshashplusownerentropy = addressHash.concat(ownerEntropy);

    var derivedBytes = Bitcoin.scrypt(passpoint, addresshashplusownerentropy, scryptParams.passpoint.N, scryptParams.passpoint.r, scryptParams.passpoint.p, 64);

    // recover the 0x02 or 0x03 prefix
    var unencryptedpubkey = [];
    unencryptedpubkey[0] = encryptedpointb[0] ^ (derivedBytes[63] & 0x01);

    decrypted1 = Bitcoin.CryptoJS.AES.decryptCompat(encryptedpointb.slice(1,17), derivedBytes.slice(32), AES_opts);
    decrypted2 = Bitcoin.CryptoJS.AES.decryptCompat(encryptedpointb.slice(17,33), derivedBytes.slice(32), AES_opts);
    decrypted = unencryptedpubkey.concat(decrypted1).concat(decrypted2);

    for (var x = 0; x < 32; x++) {
      decrypted[x+1] ^= derivedBytes[x];
    }

    var ec = ecparams.getCurve();
    var generatedPoint = curveFpDecodePointHex(ec, Bitcoin.convert.bytesToHex(decrypted));
    var generatedBytes = generatedPoint.multiply(passfactor).getEncoded(compressed);
    var generatedAddress = (new Bitcoin.Address(Bitcoin.convert.wordArrayToBytes(Bitcoin.Util.sha256ripe160(
            Bitcoin.convert.bytesToWordArray(generatedBytes))))).toString();

    var generatedAddressHash = sha256(sha256(generatedAddress)).slice(0,4);

    var valid = true;
    for (var i = 0; i < 4; i++) {
      if (addressHash[i] != generatedAddressHash[i]) {
        valid = false;
      }
    }

    return { valid: valid, address: generatedAddress };
  }

  /**
   * Checks the validity of an intermediate code.
   */
  BIP38.verifyIntermediate = function (intermediate) {
    // Simple regex check
    var regexValid = (/^passphrase[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(intermediate));
    if (!regexValid) return false;

    // Correct bytelen
    var intermediateBytes = Bitcoin.base58.decode(intermediate);
    if (intermediateBytes.length != 53)  return false;

    // Checksum check
    var expectedChecksum = intermediateBytes.slice(49,53);
    var checksum = sha256(sha256(intermediateBytes.slice(0, 49))).slice(0, 4);
    if (expectedChecksum[0] != checksum[0] ||
        expectedChecksum[1] != checksum[1] ||
        expectedChecksum[2] != checksum[2] ||
        expectedChecksum[3] != checksum[3]) {
          return false;
    }

    return true;
  }

  /**
   * Detects keys encrypted according to BIP-38 (58 base58 characters starting with 6P)
   */
  BIP38.isBIP38Format = function (string) {
    return (/^6P[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{56}$/.test(string));
  };


  return BIP38;

})();

Bitcoin.Transaction.prototype.cloneTransactionForSignature =
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
    txin.script = new Bitcoin.Script()
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

Bitcoin.Transaction.prototype.serializeOutputs = function () {
  var buffer = []

  buffer = buffer.concat(Bitcoin.convert.numToVarInt(this.outs.length))

  this.outs.forEach(function(txout) {
    buffer = buffer.concat(Bitcoin.convert.numToBytes(txout.value,8))

    var scriptBytes = txout.script.buffer
    buffer = buffer.concat(Bitcoin.convert.numToVarInt(scriptBytes.length))
    buffer = buffer.concat(scriptBytes)
  })

  return buffer
}
