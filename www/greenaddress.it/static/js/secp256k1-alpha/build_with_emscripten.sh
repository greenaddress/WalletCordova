#ZKP
# git clone https://github.com/ElementsProject/secp256k1-zkp && cd into it
./autogen.sh
emconfigure ./configure --disable-ecmult-static-precomputation --enable-experimental --enable-module-ecdh --enable-module-schnorr --enable-module-rangeproof
emcc -s NO_EXIT_RUNTIME=1 -s NO_FILESYSTEM=1 -O3 --memory-init-file 0 -DHAVE_CONFIG_H -I. -Isrc -s "EXPORTED_FUNCTIONS=['_secp256k1_pedersen_context_initialize','_secp256k1_rangeproof_context_initialize','_secp256k1_rangeproof_rewind','_secp256k1_pedersen_commit','_secp256k1_ec_pubkey_create','_secp256k1_rangeproof_sign','_secp256k1_context_randomize','_secp256k1_ecdh','_secp256k1_ec_pubkey_parse','_secp256k1_pedersen_blind_sum','_secp256k1_context_create','_secp256k1_schnorr_sign','_secp256k1_ec_pubkey_serialize','_secp256k1_ecdsa_sign','_secp256k1_ecdsa_verify','_secp256k1_ecdsa_signature_serialize_der','_secp256k1_ecdsa_signature_parse_der']" src/secp256k1.c 
