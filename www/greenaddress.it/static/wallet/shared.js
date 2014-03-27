var _currencies = {
    "BTC": {"name": "Bitcoin",
            "version": 0,
            "p2sh_version": 5,
            "base58_start": /5/,
            "compressed_start": /[LK]/},
    "BTT": {"name": "Testnet3",
            "version": 111,
            "p2sh_version": 196,
            "base58_start": /5/,
            "compressed_start": /c/}
}
// currency setup
var cur_coin_version = _currencies[cur_coin]["version"];
var cur_coin_p2sh_version = _currencies[cur_coin]["p2sh_version"];