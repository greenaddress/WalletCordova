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
Bitcoin.HDWallet.prototype.subpath = function(path_hex) {
    var key = this;
    var path_bytes = Bitcoin.convert.hexToBytes(path_hex);
    for (var i = 0; i < 32; i++) {
        key = key.derive(+Bitcoin.BigInteger.fromByteArrayUnsigned(path_bytes.slice(0, 2)));
        path_bytes = path_bytes.slice(2);
    }
    return key;
}
Bitcoin.HDWallet.prototype.subpath_for_login = function(path_hex) {
    // derive private key for signing the challenge, using 8 bytes instead of 64
    var key = this;
    var path_bytes = Bitcoin.convert.hexToBytes(path_hex);
    for (var i = 0; i < 4; i++) {
        key = key.derive(+Bitcoin.BigInteger.fromByteArrayUnsigned(path_bytes.slice(0, 2)));
        path_bytes = path_bytes.slice(2);
    }
    return key;
}