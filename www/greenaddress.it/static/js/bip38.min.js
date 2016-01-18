var bip38 = (function() {
    var scrypt = scrypt_module_factory();

    return {
        encrypt: function(input, salt_a) {
            if (!salt_a) {
                var salt_a = Bitcoin.bitcoin.crypto.hash256(input.data).slice(0, 4);
            }
            salt = new Uint8Array(salt_a);

            var key = scrypt.crypto_scrypt(scrypt.encode_utf8(input.key),
                                           salt, 16384, 8, 8, 64);
            var derivedhalf1 = key.subarray(0, 32), derivedhalf2 = key.subarray(32, 64);
            var message = [];
            for (var i = 0; i < 32; i++) {
                message.push(input.data[i] ^ derivedhalf1[i]);
            }

            var cipher = Bitcoin.aes.createCipher(
                'aes-256-ecb',
                derivedhalf2,
                salt
            );
            cipher.setAutoPadding(false);
            cipher.end(new Bitcoin.Buffer.Buffer(message));
            message = cipher.read();
            salt = new Bitcoin.Buffer.Buffer(salt);
            return Bitcoin.Buffer.Buffer.concat([message, salt]);
        },
        decrypt: function(input) {
            var bytes = input.data;
            var salt = bytes.slice(-4);
            var derivedBytes = scrypt.crypto_scrypt(scrypt.encode_utf8(input.key),
                                           salt, 16384, 8, 8, 64);

            var encrypted = bytes.slice(0, -4);

            var cipher = Bitcoin.aes.createDecipher(
                'aes-256-ecb',
                derivedBytes.subarray(32, 32+32),
                salt
            );
            cipher.setAutoPadding(false);
            cipher.end(new Bitcoin.Buffer.Buffer(encrypted));
            var decrypted = cipher.read();
            for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];

            var hash = Bitcoin.bitcoin.crypto.hash256(decrypted);
            for (var i = 0; i < 4; i++) {
                if (hash[i] != salt[i]) {
                    return {'error': 'invalid password'};
                }
            }

            return decrypted;
        }

    };
})();
