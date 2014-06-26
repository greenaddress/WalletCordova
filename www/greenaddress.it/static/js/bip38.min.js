var bip38 = (function() {
    var scrypt = scrypt_module_factory();

    return {
        encrypt: function(input, salt_a) {
            if (!salt_a) {
                var salt_a = Bitcoin.convert.wordArrayToBytes(Bitcoin.CryptoJS.SHA256(Bitcoin.CryptoJS.SHA256(
                    Bitcoin.convert.bytesToWordArray(input.data)))).slice(0, 4);
            }
            salt = new Uint8Array(salt_a);

            var key = scrypt.crypto_scrypt(scrypt.encode_utf8(input.key),
                                           salt, 16384, 8, 8, 64);
            var derivedhalf1 = key.subarray(0, 32), derivedhalf2 = key.subarray(32, 64);
            var message = [];
            for (var i = 0; i < 32; i++) {
                message.push(input.data[i] ^ derivedhalf1[i]);
            }

            var message = Bitcoin.convert.wordArrayToBytes(
                Bitcoin.CryptoJS.AES.encrypt(
                    Bitcoin.convert.bytesToWordArray(message),
                    Bitcoin.convert.bytesToWordArray(derivedhalf2),
                    {mode: Bitcoin.CryptoJS.mode.ECB,
                     padding: Bitcoin.CryptoJS.pad.NoPadding}).ciphertext);

            return message.concat(salt_a);
        },
        decrypt: function(input) {
            var bytes = input.data;
            var salt = bytes.slice(-4);
            var derivedBytes = scrypt.crypto_scrypt(scrypt.encode_utf8(input.key),
                                           salt, 16384, 8, 8, 64);

            var encrypted = Bitcoin.convert.bytesToWordArray(bytes.slice(0, -4));
            var decrypted = Bitcoin.convert.wordArrayToBytes(
                Bitcoin.CryptoJS.AES.decrypt(
                    Bitcoin.CryptoJS.lib.CipherParams.create({ciphertext: encrypted}),
                    Bitcoin.convert.bytesToWordArray(derivedBytes.subarray(32, 32+32)),
                    {mode: Bitcoin.CryptoJS.mode.ECB,
                     padding: Bitcoin.CryptoJS.pad.NoPadding}));

            for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];

            var hash = Bitcoin.convert.wordArrayToBytes(Bitcoin.CryptoJS.SHA256(Bitcoin.CryptoJS.SHA256(
                Bitcoin.convert.bytesToWordArray(decrypted))));
            for (var i = 0; i < 4; i++) {
                if (hash[i] != salt[i]) {
                    return {'error': 'invalid password'};
                }
            }

            return decrypted;
        }

    };
})();
