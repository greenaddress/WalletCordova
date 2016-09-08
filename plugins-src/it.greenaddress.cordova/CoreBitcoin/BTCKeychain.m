// Oleg Andreev <oleganza@gmail.com>

#import "BTCKeychain.h"
#import "BTCData.h"
#import "BTCKey.h"
#import "BTCBase58.h"
#import "BTCNetwork.h"
#import "../libsecp256k1/include/secp256k1.h"

#define CHECK_IF_CLEARED if (_cleared) { [[NSException exceptionWithName:@"BTCKeychain: instance was already cleared." reason:@"" userInfo:nil] raise]; }

#define BTCKeychainMainnetPrivateVersion 0x0488ADE4
#define BTCKeychainMainnetPublicVersion  0x0488B21E

#define BTCKeychainTestnetPrivateVersion 0x04358394
#define BTCKeychainTestnetPublicVersion  0x043587CF

@interface BTCKeychain ()
@property(nonatomic, readwrite) NSMutableData* chainCode;
@property(nonatomic, readwrite) NSMutableData* extendedPublicKeyData;
@property(nonatomic, readwrite) NSMutableData* extendedPrivateKeyData;
@property(nonatomic, readwrite) NSData* identifier;
@property(nonatomic, readwrite) uint32_t fingerprint;
@property(nonatomic, readwrite) uint32_t parentFingerprint;
@property(nonatomic, readwrite) uint32_t index;
@property(nonatomic, readwrite) uint8_t depth;
@property(nonatomic, readwrite) BOOL hardened;

@end

@implementation BTCKeychain {
    BOOL _cleared;
}

- (void)dealloc {
    [self clear];
}

- (void) clear {
    BTCDataClear(_chainCode);
    BTCDataClear(_extendedPublicKeyData);
    BTCDataClear(_extendedPrivateKeyData);
    BTCDataClear(_privateKey);
    BTCDataClear(_publicKey);
    _cleared = YES;
}


- (id) initWithSeed:(NSData*)seed {
    return [self initWithSeed:seed network:nil];
}

- (id) initWithSeed:(NSData*)seed network:(BTCNetwork*)network {
    if (self = [super init]) {
        if (!seed) return nil;

        NSMutableData* hmac = BTCHMACSHA512([@"Bitcoin seed" dataUsingEncoding:NSASCIIStringEncoding], seed);
        _privateKey = BTCDataRange(hmac, NSMakeRange(0, 32));
        _chainCode  = BTCDataRange(hmac, NSMakeRange(32, 32));
        BTCDataClear(hmac);

        _network = network;
    }
    return self;
}

- (id) initWithExtendedKey:(NSString*)extkey {
    return [self initWithExtendedKeyDataInternal:BTCDataFromBase58Check(extkey)];
}

- (id) initWithExtendedKeyData:(NSData*)data {
    return [self initWithExtendedKeyDataInternal:data];
}

- (id) initWithExtendedKeyDataInternal:(NSData*)extendedKeyData {
    if (self = [super init]) {
        if (extendedKeyData.length != 78) return nil;

        const uint8_t* bytes = extendedKeyData.bytes;
        uint32_t version = OSSwapBigToHostInt32(*((uint32_t*)bytes));

        uint32_t keyprefix = bytes[45];
        
        if (version == BTCKeychainMainnetPrivateVersion ||
            version == BTCKeychainTestnetPrivateVersion) {
            // Should have 0-prefixed private key (1 + 32 bytes).
            if (keyprefix != 0) return nil;
            _privateKey = BTCDataRange(extendedKeyData, NSMakeRange(46, 32));
        } else if (version == BTCKeychainMainnetPublicVersion ||
                 version == BTCKeychainTestnetPublicVersion) {
            // Should have a 33-byte public key with non-zero first byte.
            if (keyprefix == 0) return nil;
            _publicKey = BTCDataRange(extendedKeyData, NSMakeRange(45, 33));
        } else {
            // Unknown version.
            return nil;
        }

        // If it's a testnet key, remember the network.
        // Otherwise, keep it nil so we don't do extra work if it's not needed.
        if (version == BTCKeychainTestnetPrivateVersion ||
            version == BTCKeychainTestnetPublicVersion) {
            _network = [BTCNetwork testnet];
        }

        _depth = *(bytes + 4);
        _parentFingerprint = OSSwapBigToHostInt32(*((uint32_t*)(bytes + 5)));
        _index = OSSwapBigToHostInt32(*((uint32_t*)(bytes + 9)));
        
        if ((0x80000000 & _index) != 0) {
            _index = (~0x80000000) & _index;
            _hardened = YES;
        }
        
        _chainCode = BTCDataRange(extendedKeyData,NSMakeRange(13, 32));
    }
    return self;
}


#pragma mark - Properties


- (BTCNetwork*) network {
    if (!_network) {
        _network = [BTCNetwork mainnet];
    }
    return _network;
}

// deprecated
- (BTCKey*) rootKey {
    return self.key;
}

- (NSData*) extendedPrivateKeyData { return [self extendedPrivateKeyDataInternal]; }

- (NSData*) extendedPrivateKeyDataInternal {
    CHECK_IF_CLEARED;

    if (!_privateKey) return nil;
    
    if (!_extendedPrivateKeyData) {
        uint32_t version = [self.network isMainnet] ? BTCKeychainMainnetPrivateVersion : BTCKeychainTestnetPrivateVersion;
        NSMutableData* data = [self extendedKeyPrefixWithVersion:version];
        
        uint8_t padding = 0;
        [data appendBytes:&padding length:1];
        [data appendData:_privateKey];
        
        _extendedPrivateKeyData = data;
    }
    return _extendedPrivateKeyData;
}

- (NSData*) extendedPublicKeyData { return [self extendedPublicKeyDataInternal]; }

- (NSData*) extendedPublicKeyDataInternal {
    CHECK_IF_CLEARED;

    if (!_extendedPublicKeyData) {
        NSData* pubkey = self.publicKey;
        
        if (!pubkey) return nil;

        uint32_t version = [self.network isMainnet] ? BTCKeychainMainnetPublicVersion : BTCKeychainTestnetPublicVersion;
        NSMutableData* data = [self extendedKeyPrefixWithVersion:version];
        
        [data appendData:pubkey];
        
        _extendedPublicKeyData = data;
    }
    return _extendedPublicKeyData;
}

- (NSMutableData*) extendedKeyPrefixWithVersion:(uint32_t)version {
    CHECK_IF_CLEARED;

    NSMutableData* data = [NSMutableData data];
    
    version = OSSwapHostToBigInt32(version);
    [data appendBytes:&version length:sizeof(version)];
    
    [data appendBytes:&_depth length:1];
    
    uint32_t parentfp = OSSwapHostToBigInt32(_parentFingerprint);
    [data appendBytes:&parentfp length:sizeof(parentfp)];
    
    uint32_t childindex = OSSwapHostToBigInt32(_hardened ? (0x80000000 | _index) : _index);
    [data appendBytes:&childindex length:sizeof(childindex)];
    
    [data appendData:_chainCode];
    
    return data;
}

- (uint32_t) fingerprint {
    CHECK_IF_CLEARED;

    if (_fingerprint == 0) {
        const uint32_t* words = self.identifier.bytes;
        _fingerprint = OSSwapBigToHostInt32(words[0]);
    }
    return _fingerprint;
}

- (NSData*) publicKey {
    CHECK_IF_CLEARED;

    if (!_publicKey) {
        _publicKey = [[[BTCKey alloc] initWithPrivateKey:_privateKey] compressedPublicKey];
    }
    return _publicKey;
}

- (BOOL) isPrivate {
    CHECK_IF_CLEARED;
    return !!_privateKey;
}

- (BOOL) isHardened {
    CHECK_IF_CLEARED;
    return _hardened;
}

- (BTCKeychain*) derivedKeychainAtIndex:(uint32_t)index {
    return [self derivedKeychainAtIndex:index hardened:NO];
}

- (BTCKeychain*) derivedKeychainAtIndex:(uint32_t)index hardened:(BOOL)hardened {
    return [self derivedKeychainAtIndex:index hardened:hardened factor:NULL];
}

- (BTCKeychain*) derivedKeychainAtIndex:(uint32_t)index hardened:(BOOL)hardened factor:(BTCBigNumber**)factorOut {
    CHECK_IF_CLEARED;

    // As we use explicit parameter "hardened", do not allow higher bit set.
    if ((0x80000000 & index) != 0) {
        @throw [NSException exceptionWithName:@"BTCKeychain Exception"
                                       reason:@"Indexes >= 0x80000000 are invalid. Use hardened:YES argument instead." userInfo:nil];
        return nil;
    }
    
    if (!_privateKey && hardened) {
        // Not possible to derive hardened keychain without a private key.
        return nil;
    }

    BTCKeychain* derivedKeychain = [[BTCKeychain alloc] init];

    NSMutableData* data = [NSMutableData data];
    
    if (hardened) {
        uint8_t padding = 0;
        [data appendBytes:&padding length:1];
        [data appendData:_privateKey];
    } else {
        [data appendData:self.publicKey];
    }
    
    uint32_t indexBE = OSSwapHostToBigInt32(hardened ? (0x80000000 | index) : index);
    [data appendBytes:&indexBE length:sizeof(indexBE)];
    
    NSData* digest = BTCHMACSHA512(_chainCode, data);
    
    unsigned char* factor = [digest bytes];
    
    unsigned char curveOrder[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
    
    NSString* hex = BTCHexFromData(digest);
    
    bool belowOrder = false;
    for (int i = 0; i < 32; ++i) {
        if (factor[i] < curveOrder[i]) {
            belowOrder = true;
            break;
        }
    }
    
    if (!belowOrder) {
        // Factor is too big, this derivation is invalid.
        return nil;
    }
    
    // if (factorOut) *factorOut = factor;
    
    derivedKeychain.chainCode = BTCDataRange(digest, NSMakeRange(32, 32));
    
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    if (_privateKey) {
        NSMutableData *pkNumber = [NSMutableData dataWithData:_privateKey];
        
        int ret = secp256k1_ec_privkey_tweak_add(ctx, [pkNumber mutableBytes], factor);
        
        // Check for invalid derivation.
        bool nonZero = false;
        const unsigned char* pkBytes = [pkNumber bytes];
        for (int i = 0; i < [pkNumber length]; ++i) {
            if (pkBytes[i] != 0) {
                nonZero = true;
                break;
            }
        }
        if (!nonZero) {
            return nil;
        }
        
        derivedKeychain.privateKey = pkNumber;
    } else {
        secp256k1_pubkey pubkey;
        secp256k1_ec_pubkey_parse(ctx, &pubkey, [_publicKey bytes], [_publicKey length]);
        
        if (secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, factor) == 0) {
            // Check for invalid derivation.
            return nil;
        }
        
        char compressed[33];
        size_t outputlen = 33;
        secp256k1_ec_pubkey_serialize(ctx, compressed, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);
        derivedKeychain.publicKey = [NSMutableData dataWithBytes:compressed length:outputlen];
    }
    secp256k1_context_destroy(ctx);
    
    derivedKeychain.depth = _depth + 1;
    
    // requires hash160, not used by GA
    // derivedKeychain.parentFingerprint = self.fingerprint;
    
    derivedKeychain.index = index;
    derivedKeychain.hardened = hardened;
    
    return derivedKeychain;
}

- (BTCKey*) keyAtIndex:(uint32_t)index {
    return [self keyAtIndex:index hardened:NO];
}
- (BTCKey*) keyAtIndex:(uint32_t)index hardened:(BOOL)hardened {
    return [self derivedKeychainAtIndex:index hardened:hardened].key;
}


// Parses the BIP32 path and derives the chain of keychains accordingly.
// Path syntax: (m?/)?([0-9]+'?(/[0-9]+'?)*)?
// The following paths are valid:
//
// "" (root key)
// "m" (root key)
// "/" (root key)
// "m/0'" (hardened child #0 of the root key)
// "/0'" (hardened child #0 of the root key)
// "0'" (hardened child #0 of the root key)
// "m/44'/1'/2'" (BIP44 testnet account #2)
// "/44'/1'/2'" (BIP44 testnet account #2)
// "44'/1'/2'" (BIP44 testnet account #2)
//
// The following paths are invalid:
//
// "m / 0 / 1" (contains spaces)
// "m/b/c" (alphabetical characters instead of numerical indexes)
// "m/1.2^3" (contains illegal characters)
- (BTCKeychain*) derivedKeychainWithPath:(NSString*)path {

    if (path == nil) return nil;

    if ([path isEqualToString:@"m"] ||
        [path isEqualToString:@"/"] ||
        [path isEqualToString:@""]) {
        return self;
    }

    BTCKeychain* kc = self;

    if ([path rangeOfString:@"m/"].location == 0) { // strip "m/" from the beginning.
        path = [path substringFromIndex:2];
    }
    for (NSString* chunk in [path componentsSeparatedByString:@"/"]) {
        if (chunk.length == 0) {
            continue;
        }
        BOOL hardened = NO;
        NSString* indexString = chunk;
        if ([chunk rangeOfString:@"'"].location == chunk.length - 1) {
            hardened = YES;
            indexString = [chunk substringToIndex:chunk.length - 1];
        }

        // Make sure the chunk is just a number
        NSInteger i = [indexString integerValue];
        if (i >= 0 && [@(i).stringValue isEqualToString:indexString]) {
            kc = [kc derivedKeychainAtIndex:(uint32_t)i hardened:hardened];
        } else {
            return nil;
        }
    }
    return kc;
}

- (BTCKey*) keyWithPath:(NSString*)path {
    return [self derivedKeychainWithPath:path].key;
}

- (BTCKeychain*) publicKeychain {
    CHECK_IF_CLEARED;

    BTCKeychain* keychain = [[BTCKeychain alloc] init];
    
    keychain.chainCode = [self.chainCode mutableCopy];
    keychain.publicKey = [self.publicKey mutableCopy];
    keychain.parentFingerprint = self.parentFingerprint;
    keychain.index = self.index;
    keychain.depth = self.depth;
    keychain.hardened = self.hardened;
    
    return keychain;
}



// BIP44 methods.
// These methods are meant to be chained like so:
// ```
// invoiceAddress = [[rootKeychain.bitcoinMainnetKeychain keychainForAccount:1] externalKeyAtIndex:123].address
// ```


// Returns a subchain with path m/44'/0'
- (BTCKeychain*) bitcoinMainnetKeychain {
    return [[self derivedKeychainAtIndex:44 hardened:YES] derivedKeychainAtIndex:0 hardened:YES];
}

// Returns a subchain with path m/44'/1'
- (BTCKeychain*) bitcoinTestnetKeychain {
    return [[self derivedKeychainAtIndex:44 hardened:YES] derivedKeychainAtIndex:1 hardened:YES];
}

// Returns a hardened derivation for the given account index.
// Equivalent to [keychain derivedKeychainAtIndex:accountIndex hardened:YES]
- (BTCKeychain*) keychainForAccount:(uint32_t)accountIndex {
    return [self derivedKeychainAtIndex:accountIndex hardened:YES];
}

// Returns a key from an external chain (/0/i).
// BTCKey may be public-only if the receiver is public-only keychain.
- (BTCKey*) externalKeyAtIndex:(uint32_t)index {
    return [[self derivedKeychainAtIndex:0 hardened:NO] keyAtIndex:index hardened:NO];
}

// Returns a key from an internal (change) chain (/1/i).
// BTCKey may be public-only if the receiver is public-only keychain.
- (BTCKey*) changeKeyAtIndex:(uint32_t)index {
    return [[self derivedKeychainAtIndex:1 hardened:NO] keyAtIndex:index hardened:NO];
}



#pragma mark - Scanning methods.


// Scans child keys till one is found that matches the given public key.
// Limit is maximum number of keys to scan. If no key is found, returns nil.
- (BTCKeychain*) findKeychainForPublicKey:(BTCKey*)pubkey hardened:(BOOL)hardened limit:(NSUInteger)limit {
    return [self findKeychainForPublicKey:pubkey hardened:hardened from:0 limit:limit];
}

- (BTCKeychain*) findKeychainForPublicKey:(BTCKey*)pubkey hardened:(BOOL)hardened from:(uint32_t)startIndex limit:(NSUInteger)limit {
    CHECK_IF_CLEARED;

    if (!pubkey) return nil;
    if (!self.isPrivate) return nil;
    
    NSData* data = pubkey.compressedPublicKey;
    
    BTCKeychain* result = nil;
    
    for (uint32_t i = startIndex; i < (startIndex + limit); i++) {
        BTCKeychain* keychain = [self derivedKeychainAtIndex:i hardened:hardened];
        
        if ([keychain.publicKey isEqual:data]) {
            result = keychain;
            break;
        }
        
        [keychain clear];
    }
    
    BTCDataClear(data);
    
    return result;
}



#pragma mark - NSObject


- (id) copyWithZone:(NSZone *)zone {
    CHECK_IF_CLEARED;

    BTCKeychain* keychain = [[BTCKeychain alloc] init];
    
    keychain.chainCode = [self.chainCode mutableCopy];
    keychain.privateKey = [self.privateKey mutableCopy];
    if (!_privateKey) keychain.publicKey = [self.publicKey mutableCopy];
    keychain.parentFingerprint = self.parentFingerprint;
    keychain.index = self.index;
    keychain.depth = self.depth;
    keychain.hardened = self.hardened;
    
    return keychain;
}

- (BOOL) isEqual:(BTCKeychain*)other {
    CHECK_IF_CLEARED;

    if (self == other) return YES;
    
    if (self.isPrivate != other.isPrivate) return NO;
    if (self.fingerprint != other.fingerprint) return NO;
    if (self.parentFingerprint != other.parentFingerprint) return NO;
    if (self.index != other.index) return NO;
    if (self.hardened != other.hardened) return NO;
    
    if (self.isPrivate) {
        if (![self.privateKey isEqual:other.privateKey]) return NO;
    } else {
        if (![self.publicKey isEqual:other.publicKey]) return NO;
    }
    
    if (![self.chainCode isEqual:other.chainCode]) return NO;
    
    return YES;
}

- (NSUInteger) hash {
    return self.fingerprint;
}

- (NSString*) description {
    return [NSString stringWithFormat:@"<%@ %@>", [self class], self.extendedPublicKey];
}

- (NSString*) debugDescription {
    return [NSString stringWithFormat:@"<%@:0x%p depth:%d index:%x%@ parentFingerprint:%x fingerprint:%x privkey:%@ pubkey:%@ chainCode:%@>", [self class], self,
            (int)_depth,
            _index,
            _hardened ? @" hardened:YES" : @"",
            _parentFingerprint,
            self.fingerprint,
            [BTCHexFromData(self.privateKey) substringToIndex:8],
            [BTCHexFromData(self.publicKey) substringToIndex:8],
            [BTCHexFromData(self.chainCode) substringToIndex:8]
            ];
}



@end


