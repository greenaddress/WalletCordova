angular.module('greenWalletMnemonicsServices', ['greenWalletServices'])
.factory('mnemonics', ['$q', '$http', 'cordovaReady', function($q, $http, cordovaReady) {
    var mnemonics = {};
    var english_txt = require('../english').join('\n');

    var getEnglishTxt = function() {
        return $q.resolve(english_txt);
    };
    var getMnemonicMap = function() {
        return getEnglishTxt().then(function(data) {
            var words = data.split('\n');
            var mapping = {};
            for (var i = 0; i < words.length; i++) {
                mapping[words[i]] = i;
            }
            return mapping;
        });
    };
    mnemonics.getMnemonicMap = getMnemonicMap;
    mnemonics.validateMnemonic = function(mnemonic) {
        var words = mnemonic.split(" ");
        if (words.length % 3 > 0) $q.reject("Invalid number of words");
        return getMnemonicMap().then(function(mapping) {
            var indices = [];
            for (var i = 0; i < words.length; i++) {
                if (mapping[words[i]] === undefined) {
                    return $q.reject("Unknown word '" + words[i] + "'");
                }
                indices.push(mapping[words[i]]);
            }
            var binary = '';
            for (var i = 0; i < indices.length; i++) {
                var binPart = new Bitcoin.BigInteger(indices[i].toString()).toRadix(2);
                while (binPart.length < 11) binPart = '0' + binPart;
                binary += binPart;
            }
            var bits = words.length*11 - words.length/3;
            var retval = new Bitcoin.BigInteger(binary.substr(0, bits), 2).toBuffer();
            while (retval.length < bits/8) {
                retval = Bitcoin.Buffer.Buffer.concat([0], retval);
            }

            var checksum = binary.substr(bits);
            var hash = Bitcoin.bitcoin.crypto.sha256(retval);
            var binHash = '';
            for(var i = 0; i < hash.length; i++) {
                var binPart = new Bitcoin.BigInteger(hash[i].toString()).toRadix(2);
                while (binPart.length < 8) binPart = '0' + binPart;
                binHash += binPart;
            }

            if (binHash.substr(0, words.length/3) != checksum) return $q.reject('Checksum does not match');  // checksum
            return retval;
        });
    }
    mnemonics.fromMnemonic = function(mnemonic) {
        var bytes = mnemonics.validateMnemonic(mnemonic);
        var deferred = $q.defer();
        bytes.then(function(bytes) {
            deferred.resolve(bytes);
        }, function(e) {
            throw("Invalid mnemonic: " + e);
        });
        return deferred.promise;
    };
    mnemonics.toMnemonic = function(data) {
        return getEnglishTxt().then(function(response) {
            var words = response.split('\n');
            if(words.length != 2048) {
                throw("Wordlist should contain 2048 words, but it contains "+words.length+" words.");
            }
            var binary = Bitcoin.BigInteger.fromBuffer(
                new Bitcoin.Buffer.Buffer(data, 'hex')
            ).toRadix(2);
            while (binary.length < data.length*8) { binary = '0' + binary; }
            var bytes = Bitcoin.bitcoin.crypto.sha256(data);
            var hash = Bitcoin.BigInteger.fromBuffer(bytes).toRadix(2);
            while (hash.length < 256) { hash = '0' + hash; }
            binary += hash.substr(0, data.length / 4);  // checksum

            var mnemonic = [];
            for (var i = 0; i < binary.length / 11; ++i) {
                var index = new Bitcoin.BigInteger(binary.slice(i*11, (i+1)*11), 2);
                mnemonic.push(words[index[0]]);
            }
            return mnemonic.join(' ');
        });
    }
    mnemonics.seedToPath = function(seed) {
        var shaObj = new jsSHA(seed, 'HEX');
        return shaObj.getHMAC('GreenAddress.it HD wallet path', 'TEXT', 'SHA-512', 'HEX');
    }
    mnemonics.toSeed = function(mnemonic, k, validated) {
        var that = this;
        if (!validated) {
            return that.validateMnemonic(mnemonic).then(function() {
                return that.toSeed(mnemonic, k, true);
            })
        }
        var deferred = $q.defer();
        k = k || 'mnemonic';
        var m = mnemonic;
        if (window.cordova) {
            cordovaReady(function() {
                cordova.exec(function(param) {
                    if (param.constructor === Number) {
                        deferred.notify(param);
                    } else {
                        var hex = Bitcoin.Buffer.Buffer(
                            new Uint8Array(param)
                        ).toString('hex');
                        deferred.resolve(hex);
                    }
                }, function(fail) {
                    console.log('mnemonic.toSeed failed: ' + fail)
                }, "BIP39", "calcSeed", [k, m]);
            })();
        } else {
            var worker = new Worker(BASE_URL+"/static/js/greenwallet/mnemonics/mnemonic_seed_worker.js");
            worker.postMessage({k: k, m: m});
            worker.onmessage = function(message) {
                if(message.data.type == 'seed') {
                    deferred.resolve(message.data.seed);
                } else {
                    deferred.notify(message.data.progress);
                }
            }
        }
        return deferred.promise;
    };
    return mnemonics;
}]);
