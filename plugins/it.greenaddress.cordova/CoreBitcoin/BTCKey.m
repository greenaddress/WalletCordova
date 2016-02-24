// Oleg Andreev <oleganza@gmail.com>

#import "BTCKey.h"
#import "BTCData.h"
#import "BTCAddress.h"
#import "../libsecp256k1/include/secp256k1.h"
#include <CommonCrypto/CommonCrypto.h>

#define CHECK_IF_CLEARED if (_cleared) { [[NSException exceptionWithName:@"BTCKey: instance was already cleared." reason:@"" userInfo:nil] raise]; }

#define BTCCompressedPubkeyLength   (33)
#define BTCUncompressedPubkeyLength (65)

static BOOL    BTCKeyCheckPrivateKeyRange(const unsigned char *secret, size_t length);
static BOOL    BTCKeyCheckSignatureElement(const unsigned char *bytes, int length, BOOL half);

@interface BTCKey ()
@end

@implementation BTCKey {
    BOOL _cleared;
    NSMutableData* _key;
    NSMutableData* _publicKey;
    BOOL _publicKeyCompressed;
}

- (id) initWithNewKeyPair:(BOOL)createKeyPair {
    if (self = [super init]) {
        if (createKeyPair) {
            exit(0); // not implemented
        }
    }
    return self;
}

- (id) init {
    return [self initWithNewKeyPair:YES];
}

- (id) initWithPublicKey:(NSData*)publicKey {
    if (self = [super init]) {
        if (![self isValidPubKey:publicKey]) return nil;
        [self setPublicKey:publicKey];
    }
    return self;
}

- (id) initWithWIF:(NSString*)wifString {
    BTCPrivateKeyAddress* addr = [BTCPrivateKeyAddress addressWithString:wifString];
    if (![addr isKindOfClass:[BTCPrivateKeyAddress class]]) {
        return nil;
    }
    return [self initWithPrivateKeyAddress:addr];
}

- (id) initWithPrivateKey:(NSData*)privateKey {
    if (self = [super init]) {
        [self setPrivateKey:privateKey];
    }
    return self;
}

- (void) clear {
    BTCDataClear(_publicKey);
    _publicKey = nil;

    BTCDataClear(_key);
    _key = nil;

    _cleared = YES;
}


- (void) dealloc {
    [self clear];
}


- (NSMutableData*) publicKey {
    CHECK_IF_CLEARED;
    return [NSMutableData dataWithData:[self publicKeyCached]];
}

- (NSMutableData*) publicKeyCached {
    CHECK_IF_CLEARED;
    if (!_publicKey) {
        _publicKey = [self publicKeyWithCompression:_publicKeyCompressed];
    }
    return _publicKey;
}

- (NSMutableData*) compressedPublicKey {
    return [self publicKeyWithCompression:YES];
}

- (NSMutableData*) uncompressedPublicKey {
    return [self publicKeyWithCompression:NO];
}


- (NSMutableData*) publicKeyWithCompression:(BOOL)compression {
    CHECK_IF_CLEARED;
    if (!_key) return nil;
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, [_key bytes]);
    size_t outputlen = 65;
    unsigned char output[65];
    secp256k1_ec_pubkey_serialize(ctx, output, &outputlen, &pubkey, compression ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    secp256k1_context_destroy(ctx);
    
    NSMutableData* data = [[NSMutableData alloc] initWithBytes:output length:outputlen];
    return data;
}

- (NSMutableData*) privateKey {
    CHECK_IF_CLEARED;

    return [[NSMutableData alloc] initWithData:_key];
}

- (NSString*) WIF {
    if (!self.privateKey) return nil;
    return [self privateKeyAddress].string;
}

- (NSString*) WIFTestnet {
    if (!self.privateKey) return nil;
    return [self privateKeyAddressTestnet].string;
}

- (void) setPublicKey:(NSData *)publicKey {
    CHECK_IF_CLEARED;
    if (publicKey.length == 0) return;
    _publicKey = [NSMutableData dataWithData:publicKey];
    
    _publicKeyCompressed = ([self lengthOfPubKey:_publicKey] == BTCCompressedPubkeyLength);
}
/*
- (void) setDERPrivateKey:(NSData *)DERPrivateKey {
    CHECK_IF_CLEARED;
    if (!DERPrivateKey) return;
    
    BTCDataClear(_publicKey); _publicKey = nil;
    [self prepareKeyIfNeeded];
    
    const unsigned char* bytes = DERPrivateKey.bytes;
    if (!d2i_ECPrivateKey(&_key, &bytes, DERPrivateKey.length)) {
        // OpenSSL failed for some weird reason. I have no idea what we should do.
    }
}
*/
- (void) setPrivateKey:(NSData *)privateKey {
    CHECK_IF_CLEARED;
    if (!privateKey) return;
    
    BTCDataClear(_publicKey); _publicKey = nil;
    _key = [NSMutableData dataWithData:privateKey];
}

- (BOOL) isPublicKeyCompressed {
    CHECK_IF_CLEARED;
    return _publicKeyCompressed;
}

- (void) setPublicKeyCompressed:(BOOL)flag {
    CHECK_IF_CLEARED;
    _publicKey = nil;
    _publicKeyCompressed = flag;
}



#pragma mark - NSObject


- (BOOL) isEqual:(BTCKey*)otherKey {
    CHECK_IF_CLEARED;
    if (![otherKey isKindOfClass:[self class]]) return NO;
    return [self.publicKeyCached isEqual:otherKey.publicKeyCached];
}

- (NSUInteger) hash {
    CHECK_IF_CLEARED;
    return [self.publicKeyCached hash];
}

- (NSString*) description {
    return [NSString stringWithFormat:@"<BTCKey:0x%p %@>", self, BTCHexFromData(self.publicKeyCached)];
}

- (NSString*) debugDescription
{
    return [NSString stringWithFormat:@"<BTCKey:0x%p pubkey:%@ privkey:%@>", self, BTCHexFromData(self.publicKeyCached), BTCHexFromData(self.privateKey)];
}



- (NSUInteger) lengthOfPubKey:(NSData*)data {
    if (data.length == 0) return 0;
    
    unsigned char header = ((const unsigned char*)data.bytes)[0];
    if (header == 2 || header == 3)
        return BTCCompressedPubkeyLength;
    if (header == 4 || header == 6 || header == 7)
        return BTCUncompressedPubkeyLength;
    return 0;
}

- (BOOL) isValidPubKey:(NSData*)data {
    CHECK_IF_CLEARED;
    NSUInteger length = data.length;
    return length > 0 && [self lengthOfPubKey:data] == length;
}





#pragma mark - BTCAddress Import/Export




- (id) initWithPrivateKeyAddress:(BTCPrivateKeyAddress*)privateKeyAddress {
    if (self = [self initWithNewKeyPair:NO]) {
        [self setPrivateKey:privateKeyAddress.data];
        [self setPublicKeyCompressed:privateKeyAddress.publicKeyCompressed];
    }
    return self;
}

- (BTCPublicKeyAddress*) publicKeyAddress {
    CHECK_IF_CLEARED;
    NSData* pubkey = [self publicKeyCached];
    if (pubkey.length == 0) return nil;
    return [BTCPublicKeyAddress addressWithData:BTCHash160(pubkey)];
}

- (BTCPrivateKeyAddress*) privateKeyAddress {
    CHECK_IF_CLEARED;
    NSMutableData* privkey = self.privateKey;
    if (privkey.length == 0) return nil;
    
    BTCPrivateKeyAddress* result = [BTCPrivateKeyAddress addressWithData:privkey publicKeyCompressed:self.isPublicKeyCompressed];
    BTCDataClear(privkey);
    return result;
}


- (BTCPrivateKeyAddressTestnet*) privateKeyAddressTestnet {
    CHECK_IF_CLEARED;
    NSMutableData* privkey = self.privateKey;
    if (privkey.length == 0) return nil;

    BTCPrivateKeyAddressTestnet* result = [BTCPrivateKeyAddressTestnet addressWithData:privkey publicKeyCompressed:self.isPublicKeyCompressed];
    BTCDataClear(privkey);
    return result;
}







#pragma mark - Compact Signature


// Verifies signature of the hash with its public key.
- (BOOL) isValidCompactSignature:(NSData*)signature forHash:(NSData*)hash {
    CHECK_IF_CLEARED;
    BTCKey* key = [[self class] verifyCompactSignature:signature forHash:hash];
    return [key isEqual:self];
}













#pragma mark - Bitcoin Signed Message





// Returns a signature for a message prepended with "Bitcoin Signed Message:\n" line.
- (NSData*) signatureForMessage:(NSString*)message {
    return [self signatureForBinaryMessage:[message dataUsingEncoding:NSASCIIStringEncoding]];
}
// Verifies message against given signature. On success returns a public key.
+ (BTCKey*) verifySignature:(NSData*)signature forMessage:(NSString*)message {
    return [self verifySignature:signature forBinaryMessage:[message dataUsingEncoding:NSASCIIStringEncoding]];
}
- (BOOL) isValidSignature:(NSData*)signature forMessage:(NSString*)message {
    return [self isValidSignature:signature forBinaryMessage:[message dataUsingEncoding:NSASCIIStringEncoding]];
}

- (BOOL) isValidSignature:(NSData*)signature forBinaryMessage:(NSData *)data {
    BTCKey* key = [[self class] verifySignature:signature forBinaryMessage:data];
    return [key isEqual:self];
}







#pragma mark - Canonical Checks


+ (BOOL) isCanonicalSignatureWithHashType:(NSData*)data verifyEvenS:(BOOL)verifyLowerS error:(NSError**)errorOut { // deprecated
    return [self isCanonicalSignatureWithHashType:data verifyLowerS:verifyLowerS error:errorOut];
}

@end



// Order of secp256k1's generator minus 1.
static const unsigned char BTCKeyMaxModOrder[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
};

// Half of the order of secp256k1's generator minus 1.
static const unsigned char BTCKeyMaxModHalfOrder[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

static const unsigned char BTCKeyZero[0] = {};

NSComparisonResult BTCKeyCompareBigEndian(const unsigned char *c1, size_t c1len,
                                          const unsigned char *c2, size_t c2len) {
    while (c1len > c2len) {
        if (*c1 > 0) return NSOrderedDescending;
        c1++;
        c1len--;
    }
    while (c2len > c1len) {
        if (*c2 > 0) return NSOrderedAscending;
        c2++;
        c2len--;
    }
    while (c1len > 0) {
        if (*c1 > *c2) return NSOrderedDescending;
        if (*c2 > *c1) return NSOrderedAscending;
        c1++;
        c2++;
        c1len--;
    }
    return NSOrderedSame;
}

static BOOL BTCKeyCheckPrivateKeyRange(const unsigned char *secret, size_t length) {
    return BTCKeyCompareBigEndian(secret, length, BTCKeyZero, 0) > 0 &&
           BTCKeyCompareBigEndian(secret, length, BTCKeyMaxModOrder, 32) <= 0;
}

static BOOL BTCKeyCheckSignatureElement(const unsigned char *bytes, int length, BOOL half) {
    return BTCKeyCompareBigEndian(bytes, length, BTCKeyZero, 0) > 0 &&
           BTCKeyCompareBigEndian(bytes, length, half ? BTCKeyMaxModHalfOrder : BTCKeyMaxModOrder, 32) <= 0;
}


