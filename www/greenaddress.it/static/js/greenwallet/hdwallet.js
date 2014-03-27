var GAHDWallet = function(data) {
    this.ecparams = secp256k1();
    if (data.seed_hex) {
        var shaObj = new jsSHA(data.seed_hex, 'HEX');
        var master_hex = shaObj.getHMAC('Bitcoin seed', 'TEXT', 'SHA-512', 'HEX');
        var tmp = master_hex, bytes = [];
        while (tmp.length >= 2) {
            bytes.push(parseInt(tmp.substring(0, 2), 16));
            tmp = tmp.substring(2, tmp.length);
        }
        this.secret_exponent_hex = master_hex.slice(0, 64);
        this.secret_exponent_bytes = bytes.slice(0, 32);
        this.secret_exponent = BigInteger.fromByteArrayUnsigned(this.secret_exponent_bytes);
        this.chain_code_hex = master_hex.slice(64, 128);
        this.chain_code_bytes = bytes.slice(32, 64);
        this.depth = 0;
        this.child_number_bytes = [0, 0, 0, 0];
        this.parent_fingerprint = [0, 0, 0, 0];
        this.seed_hex = data.seed_hex;
    }
    if (data.chain_code_hex) {
        this.chain_code_hex = data.chain_code_hex;
        this.chain_code_bytes = new BigInteger(data.chain_code_hex, 16).toByteArrayUnsigned();
        while (this.chain_code_bytes.length < 32) {
            this.chain_code_bytes.unshift(0);
        }
    }
    if (data.secret_exponent_hex) {
        this.secret_exponent_hex = data.secret_exponent_hex;
        this.secret_exponent = new BigInteger(data.secret_exponent_hex, 16)
        this.secret_exponent_bytes = this.secret_exponent.toByteArrayUnsigned();
        while (this.secret_exponent_bytes.length < 32) {
            this.secret_exponent_bytes.unshift(0);
        }
        this.secret_exponent = BigInteger.fromByteArrayUnsigned(this.secret_exponent_bytes);
    } else if (data.public_key) {
        this.public_key = data.public_key;
    } else if (data.public_key_hex) {
        this.public_key = this.ecparams.curve.decodePointHex(data.public_key_hex);
    }
    if (data.depth) {
        this.depth = data.depth;
    }
    if (!this.public_key) {
        this.public_key = this.ecparams.getG().multiply(this.secret_exponent);
    }
    if (data.child_number_bytes) {
        this.child_number_bytes = data.child_number_bytes;
    }
    if (data.parent_fingerprint) {
        this.parent_fingerprint = data.parent_fingerprint;
    }
};

GAHDWallet.prototype.getEncodedPub = function() {
    var enc = [0x04, 0x88, 0xB2, 0x1E];  // version
    enc = enc.concat([this.depth]);  // depth
    enc = enc.concat(this.parent_fingerprint);  // parent key fingerprint
    enc = enc.concat(this.child_number_bytes);  // child number
    enc = enc.concat(this.chain_code_bytes);
    enc = enc.concat(this.public_key.getEncoded(true));
    var checksum = Crypto.SHA256(Crypto.SHA256(enc, {asBytes: true}), {asBytes: true});
    enc = enc.concat(checksum.slice(0, 4));
    return B58.encode(enc);
};

GAHDWallet.prototype.getEncodedPrv = function() {
    if (!this.secret_exponent_bytes) throw gettext("You can't sent funds in watch only mode");
    var enc = [0x04, 0x88, 0xAD, 0xE4];  // version
    enc = enc.concat([this.depth]);  // depth
    enc = enc.concat(this.parent_fingerprint);  // parent key fingerprint
    enc = enc.concat(this.child_number_bytes);  // child number
    enc = enc.concat(this.chain_code_bytes);
    enc = enc.concat([0]);  // private key follows 0x00
    enc = enc.concat(this.secret_exponent_bytes);
    var checksum = Crypto.SHA256(Crypto.SHA256(enc, {asBytes: true}), {asBytes: true});
    enc = enc.concat(checksum.slice(0, 4));
    return B58.encode(enc);
}

GAHDWallet.prototype.getPubKeyHash = function() {
    return Bitcoin.Util.sha256ripe160(this.public_key.getEncoded(true));
}

GAHDWallet.prototype.getBitcoinAddress = function() {
    var hash = this.getPubKeyHash();
    return new Bitcoin.Address(hash);
}

GAHDWallet.prototype.getFingerprint = function() {
    return this.getPubKeyHash().slice(0, 4);
}

GAHDWallet.prototype.subkey = function(i, is_prime, as_private) {
    if ((is_prime || as_private) && !this.secret_exponent) throw gettext("You can't sent funds in watch only mode");
    var i = new BigInteger(i.toString());
    if (is_prime) {
        i = i.or(new BigInteger('80000000', 16));
    }
    var i_as_hex = i.toRadix(16);
    while (i_as_hex.length < 8) i_as_hex = '0' + i_as_hex;
    var data;
    if (is_prime) {
        data = '00' + this.secret_exponent_hex + i_as_hex;
    } else {
        data = BigInteger.fromByteArrayUnsigned(this.public_key.getEncoded(true)).toRadix(16);
        while(data.length < 66) data = '0' + data;
        data += i_as_hex;
    }
    var shaObj = new jsSHA(data, 'HEX');
    var I = shaObj.getHMAC(this.chain_code_hex, 'HEX', 'SHA-512', 'HEX');
    var I_l = new BigInteger(I.slice(0, 64), 16);

    var data = {chain_code_hex: I.slice(64, 128),
                depth: this.depth + 1,
                parent_fingerprint: this.getFingerprint(),
                child_number_bytes: Crypto.util.hexToBytes(i_as_hex)};
    if (as_private) {
        var secret_exponent = I_l.add(this.secret_exponent).mod(this.ecparams.n);
        data.secret_exponent_hex = secret_exponent.toRadix(16);
        while (data.secret_exponent_hex.length < 64) {
            data.secret_exponent_hex = '0' + data.secret_exponent_hex;
        }
    } else {
        data.public_key = this.ecparams.getG().multiply(I_l).add(this.public_key);
    }
    return new GAHDWallet(data);
}
GAHDWallet.prototype.subpath = function(path_hex) {
    var key = this;
    var path_bytes = Crypto.util.hexToBytes(path_hex);
    for (var i = 0; i < 32; i++) {
        key = key.subkey(+BigInteger.fromByteArrayUnsigned(path_bytes.slice(0, 2)), false, false);
        path_bytes = path_bytes.slice(2);
    }
    return key;
}