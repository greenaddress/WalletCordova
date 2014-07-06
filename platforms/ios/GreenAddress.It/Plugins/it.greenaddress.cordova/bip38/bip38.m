//
//  bip38.m
//  bip38
//
//  Copyright (c) 2014 GreenAddress. All rights reserved.
//

#import "bip38.h"
#import "crypto_scrypt.h"
#import <CoreBitcoin/BTCBase58.h>
#import <CoreBitcoin/BTCData.h>
#import <CoreBitcoin/BTCBigNumber.h>
#import <CoreBitcoin/BTCCurvePoint.h>
#import <CoreBitcoin/BTCKey.h>
#import <CoreBitcoin/BTCAddress.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>

@implementation bip38

+ (NSString*) decode:(NSString*)encoded
        withPassword:(NSString*)password
               error:(NSError**)error {
    NSData* data = BTCDataFromBase58Check(encoded);
    if (data == nil || [data length] != 39) {
        *error = [NSError errorWithDomain:@"invalid_privkey" code:0 userInfo:nil];
        return nil;
    }
    const uint8_t* bytes = [data bytes];
    bool compressed = false, ec = false, hasLot = false;

    if ((bytes[1] & 0xff) == 0x42)
    {
        if ((bytes[2] & 0xff) == 0xc0) {
            // non-EC-multiplied keys without compression (prefix 6PR)
        } else if ((bytes[2] & 0xff) == 0xe0) {
            // non-EC-multiplied keys with compression (prefix 6PY)
            compressed = true;
        } else {
            *error = [NSError errorWithDomain:@"invalid_privkey" code:0 userInfo:nil];
            return nil;
        }
    } else if ((bytes[1] & 0xff) == 0x43) {
        // EC-multiplied keys without compression (prefix 6Pf)
        // EC-multiplied keys with compression (prefix 6Pn)
        ec = true;
        compressed = (bytes[2] & 0x20) != 0;
        hasLot = (bytes[2] & 0x04) != 0;
        if ((bytes[2] & 0x24) != bytes[2]) {
            *error = [NSError errorWithDomain:@"invalid_privkey" code:0 userInfo:nil];
            return nil;
        }
    } else {
        *error = [NSError errorWithDomain:@"invalid_privkey" code:0 userInfo:nil];
        return nil;
    }

    const uint8_t* priv;
    if (ec) {
        priv = [bip38 _decode_ec:bytes
                        password:password
                          hasLot:hasLot];
    } else {
        // passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen
        const uint8_t* password_bytes = (const uint8_t*)[password UTF8String];
        uint8_t buf[64];
        crypto_scrypt(password_bytes,
                      [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                      bytes+3, 4,
                      16384, 8, 8, buf, 64);
        
        uint8_t decrypted[32];
        size_t outLength;
        CCCryptorStatus result = CCCrypt(kCCDecrypt, // operation
                                         kCCAlgorithmAES, // Algorithm
                                         kCCOptionECBMode, // options
                                         buf+32, // key
                                         32, // keylength
                                         nil, // iv
                                         bytes+3+4, // dataIn
                                         32, // dataInLength,
                                         decrypted, // dataOut
                                         32, // dataOutAvailable
                                         &outLength); // dataOutMoved
        for (int i = 0; i < 32; ++i) {
            decrypted[i] ^= buf[i];
        }
        
        priv = decrypted;
    }
    
    BTCKey* key = [[BTCKey alloc] initWithPrivateKey:[[NSData alloc] initWithBytes:priv length:32]];
    [key setCompressedPublicKey:compressed];
    NSString* addr = [[key publicKeyAddress] base58String];
    NSData* hash = BTCHash256([addr dataUsingEncoding:NSUTF8StringEncoding]);
    const uint8_t* hash_bytes = [hash bytes];
    for (int i = 0; i < 4; ++i) {
        if (bytes[i+3] != hash_bytes[i]) {
            *error = [NSError errorWithDomain:@"invalid_passphrase" code:0 userInfo:nil];
            return nil;
        }
    }
    
    return [[key privateKeyAddress] base58String];
}

+ (const uint8_t*) _decode_ec:(const uint8_t*)bytes
                     password:(NSString*)password
                       hasLot:(bool)hasLot {
    // passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen
    const uint8_t* password_bytes = (const uint8_t*)[password UTF8String];
    uint8_t passfactor[32];
    crypto_scrypt(password_bytes, [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                  bytes+7, hasLot ? 4 : 8,
                  16384, 8, 8, passfactor, 32);
    if (hasLot) {
        NSMutableData* tmp = [[NSData dataWithBytes:passfactor length:32] mutableCopy];
        [tmp appendBytes:bytes+7 length:8];
        NSData* hash = BTCHash256(tmp);
        const uint8_t* hash_bytes = [hash bytes];
        for (int i = 0; i < 32; ++i) passfactor[i] = hash_bytes[i];
    }
    
    BTCKey* key = [[BTCKey alloc] initWithPrivateKey:[NSData dataWithBytes:passfactor
                                                                    length:32]];
    uint8_t derived[64];
    crypto_scrypt([[key publicKeyCompressed:true] bytes], 33,
                  bytes+3, 12,
                  1024, 1, 1, derived, 64);
    
    uint8_t decrypted2[16];
    size_t outLength;
    CCCryptorStatus result = CCCrypt(kCCDecrypt, // operation
                                     kCCAlgorithmAES, // Algorithm
                                     kCCOptionECBMode, // options
                                     derived+32, // key
                                     32, // keylength
                                     nil, // iv
                                     bytes+23, // dataIn
                                     16, // dataInLength,
                                     decrypted2, // dataOut
                                     16, // dataOutAvailable
                                     &outLength); // dataOutMoved
    for (int i = 0; i < 16; ++i) {
        decrypted2[i] ^= derived[i+16];
    }
    
    NSMutableData* encrypted1 = [[NSData dataWithBytes:bytes+15 length:8] mutableCopy];
    [encrypted1 appendBytes:decrypted2 length:8];
    
    uint8_t decrypted1[16];
    result = CCCrypt(kCCDecrypt, // operation
                     kCCAlgorithmAES, // Algorithm
                     kCCOptionECBMode, // options
                     derived+32, // key
                     32, // keylength
                     nil, // iv
                     [encrypted1 bytes], // dataIn
                     16, // dataInLength,
                     decrypted1, // dataOut
                     16, // dataOutAvailable
                     &outLength); // dataOutMoved
    for (int i = 0; i < 16; ++i) {
        decrypted1[i] ^= derived[i];
    }
    
    uint8_t seed[24];
    for (int i = 0; i < 16; ++i) seed[i] = decrypted1[i];
    for (int i = 0; i < 8; ++i) seed[16+i] = decrypted2[8+i];
    
    BTCMutableBigNumber* priv = [[BTCMutableBigNumber alloc] initWithUnsignedData:[NSData dataWithBytes:passfactor length:32]];
    [priv multiply:[[BTCBigNumber alloc]
                    initWithUnsignedData:BTCHash256([NSData dataWithBytes:seed length:24])]
                                     mod:[BTCCurvePoint curveOrder]];
    
    return [[priv unsignedData] bytes];
}

+ (NSString*) encode:(NSString*)b58
        withPassword:(NSString*)password {
    BTCPrivateKeyAddress* addr = [BTCPrivateKeyAddress addressWithBase58String:b58];
    BTCKey* key = [[BTCKey alloc] initWithPrivateKeyAddress:addr];
    NSMutableData* data = [[key privateKey] mutableCopy];
    uint8_t* decrypted = [data mutableBytes];
    uint8_t store[39];
    
    store[0] = 0x01;
    store[1] = 0x42;
    store[2] = [key isCompressedPublicKey] ? 0xe0 : 0xc0;
    
    NSString* b58_addr = [[key publicKeyAddress] base58String];
    NSData* hash = BTCHash256([b58_addr dataUsingEncoding:NSUTF8StringEncoding]);
    const uint8_t* hash_bytes = [hash bytes];
    for (int i = 0; i < 4; ++i) {
        store[3+i] = hash_bytes[i];
    }
    
    // passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen
    const uint8_t* password_bytes = (const uint8_t*)[password UTF8String];
    uint8_t buf[64];
    crypto_scrypt(password_bytes, [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                  hash_bytes, 4,
                  16384, 8, 8, buf, 64);
    
    uint8_t encrypted[32];
    size_t outLength;
    
    for (int i = 0; i < 32; ++i) {
        decrypted[i] ^= buf[i];
    }
    CCCryptorStatus result = CCCrypt(kCCEncrypt, // operation
                                     kCCAlgorithmAES, // Algorithm
                                     kCCOptionECBMode, // options
                                     buf+32, // key
                                     32, // keylength
                                     nil, // iv
                                     decrypted, // dataIn
                                     32, // dataInLength,
                                     encrypted, // dataOut
                                     32, // dataOutAvailable
                                     &outLength); // dataOutMoved
    
    for (int i = 0; i < 32; ++i) {
        store[i+7] = encrypted[i];
    }
    
    return BTCBase58CheckStringWithData([[NSData alloc] initWithBytes:store length:39]);
}


@end
