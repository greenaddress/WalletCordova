// compiled from https://gist.github.com/shesek/5835695  and  modified (Math.pow(2, (8 * i)) instead of << to parse 0xFFFFFFFF correctly)

var decode_raw_tx;

decode_raw_tx = (function() {
  var Transaction, TransactionIn, TransactionOut, bytesToBase64, parse_int, u16, u32, u64, u8, varchar, varint;
  Transaction = Bitcoin.Transaction, TransactionIn = Bitcoin.TransactionIn, TransactionOut = Bitcoin.TransactionOut;
  bytesToBase64 = Crypto.util.bytesToBase64;
  parse_int = function(size) {
    return function(bytes) {
      var i, n, _i;
      n = 0;
      for (i = _i = 0; 0 <= size ? _i < size : _i > size; i = 0 <= size ? ++_i : --_i) {
        n += (bytes.shift() & 0xff) * Math.pow(2, (8 * i));
      }
      return n;
    };
  };
  u8 = function(bytes) {
    return bytes.shift();
  };
  u16 = parse_int(2);
  u32 = parse_int(4);
  u64 = function(bytes) {
    return bytes.splice(0, 8);
  };
  varint = function(bytes) {
    var n;
    switch (n = u8(bytes)) {
      case 0xfd:
        return u16(bytes);
      case 0xfe:
        return u32(bytes);
      case 0xff:
        return u64(bytes);
      default:
        return n;
    }
  };
  varchar = function(bytes) {
    return bytes.splice(0, varint(bytes));
  };
  return function(bytes) {
    var in_count, out_count, tx, ver, _i, _j;
    bytes = bytes.slice();
    ver = u32(bytes);
    if (ver !== 0x01) {
      throw new Error('Unsupported version');
    }
    tx = new Transaction;
    in_count = varint(bytes);
    for (_i = 0; 0 <= in_count ? _i < in_count : _i > in_count; 0 <= in_count ? _i++ : _i--) {
      tx.addInput(new TransactionIn({
        outpoint: {
          hash: bytesToBase64(bytes.splice(0, 32)),
          index: u32(bytes)
        },
        script: varchar(bytes),
        sequence: u32(bytes)
      }));
    }
    out_count = varint(bytes);
    for (_j = 0; 0 <= out_count ? _j < out_count : _j > out_count; 0 <= out_count ? _j++ : _j--) {
      tx.addOutput(new TransactionOut({
        value: u64(bytes),
        script: varchar(bytes)
      }));
    }
    tx.lock_time = u32(bytes);
    return tx;
  };
})();
