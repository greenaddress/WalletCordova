//
//  CDVBIP38.m
//  GreenAddress.It
//

#import "CDVBIP38.h"
#import "bip38/bip38.h"
#import "crypto_scrypt.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CoreBitcoin/BTCData.h>
#import <CoreBitcoin/BTCAddress.h>
#import <CoreBitcoin/BTCKey.h>

@implementation CDVBIP38

- (void)decrypt_raw:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        NSArray* encrypted = [command.arguments objectAtIndex:0];
        uint8_t encrypted_bytes[36];
        for (int i = 0; i < 36; ++i) {
            encrypted_bytes[i] = [(NSNumber*)[encrypted objectAtIndex:i] intValue];
        }
        NSString* password = [command.arguments objectAtIndex:1];
        
        

        const uint8_t* password_bytes = (const uint8_t*)[password UTF8String];
        uint8_t buf[64];
        // passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen
        crypto_scrypt(password_bytes, [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                      encrypted_bytes+32, 4,
                      16384, 8, 8, buf, 64);
        
        uint8_t decrypted[32];
        size_t outLength;
        CCCryptorStatus result = CCCrypt(kCCDecrypt, // operation
                                         kCCAlgorithmAES, // Algorithm
                                         kCCOptionECBMode, // options
                                         buf+32, // key
                                         32, // keylength
                                         nil, // iv
                                         encrypted_bytes, // dataIn
                                         32, // dataInLength,
                                         decrypted, // dataOut
                                         32, // dataOutAvailable
                                         &outLength); // dataOutMoved
        for (int i = 0; i < 32; ++i) {
            decrypted[i] ^= buf[i];
        }
        
        NSData *hash_data = BTCHash256([[NSData alloc] initWithBytes:decrypted length:32]);
        const uint8_t *hash_bytes = [hash_data bytes];
        for (int i = 0; i < 4; ++i) {
            if (hash_bytes[i] != encrypted_bytes[32+i]) {
                CDVPluginResult* pluginResult = [CDVPluginResult
                                                 resultWithStatus:CDVCommandStatus_ERROR
                                                  messageAsString:@"invalid password"];
                [self.commandDelegate sendPluginResult:pluginResult
                                            callbackId:command.callbackId];
                return;
            }
        }
        

        NSMutableArray* result_arr = [[NSMutableArray alloc] init];
        for (int i = 0; i < 32; i++)
            [result_arr addObject:[[NSNumber alloc] initWithUnsignedChar:decrypted[i]]];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                           messageAsArray:result_arr];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)encrypt_raw:(CDVInvokedUrlCommand*)command
{
    
    [self.commandDelegate runInBackground:^{
        NSArray* decrypted = [command.arguments objectAtIndex:0];
        uint8_t decrypted_bytes[32];
        for (int i = 0; i < 32; ++i) {
            decrypted_bytes[i] = [(NSNumber*)[decrypted objectAtIndex:i] intValue];
        }
        NSString* password = [command.arguments objectAtIndex:1];
        
        NSData* decrypted_data = [[NSData alloc] initWithBytes:decrypted_bytes
                                                        length:32];
        NSData* hash_data = BTCHash256(decrypted_data);
        
        const uint8_t* password_bytes = (const uint8_t*)[password UTF8String];
        uint8_t buf[64];
        // passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen
        crypto_scrypt(password_bytes, [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
                      [hash_data bytes], 4,
                      16384, 8, 8, buf, 64);
        
        for (int i = 0; i < 32; ++i) {
            decrypted_bytes[i] ^= buf[i];
        }
        uint8_t encrypted[32];
        size_t outLength;
        CCCryptorStatus result = CCCrypt(kCCEncrypt, // operation
                                         kCCAlgorithmAES, // Algorithm
                                         kCCOptionECBMode, // options
                                         buf+32, // key
                                         32, // keylength
                                         nil, // iv
                                         decrypted_bytes, // dataIn
                                         32, // dataInLength,
                                         encrypted, // dataOut
                                         32, // dataOutAvailable
                                         &outLength); // dataOutMoved
        
        NSMutableArray* result_arr = [[NSMutableArray alloc] init];
        for (int i = 0; i < 32; i++)
            [result_arr addObject:[[NSNumber alloc] initWithUnsignedChar:encrypted[i]]];
        const uint8_t *hash_bytes = [hash_data bytes];
        for (int i = 0; i < 4; i++)
            [result_arr addObject:[[NSNumber alloc] initWithUnsignedChar:hash_bytes[i]]];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                           messageAsArray:result_arr];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];

}

- (void)decrypt:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        NSString* b58 = [command.arguments objectAtIndex:0];
        NSString* password = [command.arguments objectAtIndex:1];
        NSString* cur_coin = [command.arguments objectAtIndex:2];  // not used
        
        NSError* error;
        NSString* result = [bip38 decode:b58 withPassword:password
                                   error:&error];
        CDVPluginResult* pluginResult;
        if (result == nil) {
             pluginResult =
                [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                  messageAsString:[error domain]];
            
        } else {
            pluginResult =
                [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                  messageAsString:result];
        }
        [self.commandDelegate sendPluginResult:pluginResult
                                    callbackId:command.callbackId];
    }];
}

- (void)encrypt:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        NSArray* key = [command.arguments objectAtIndex:0];
        uint8_t key_bytes[32];
        for (int i = 0; i < 32; ++i) {
            key_bytes[i] = [(NSNumber*)[key objectAtIndex:i] intValue];
        }
        
        NSString* password = [command.arguments objectAtIndex:1];
        NSString* cur_coin = [command.arguments objectAtIndex:2];  // not used
        
        BTCPrivateKeyAddress* address =
            [BTCPrivateKeyAddress addressWithData:[NSData dataWithBytes:key_bytes length:32]
                              compressedPublicKey:true];
        NSString* serializedKey = [bip38 encode:[address base58String]
                                   withPassword:password];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                          messageAsString:serializedKey];
        [self.commandDelegate sendPluginResult:pluginResult
                                    callbackId:command.callbackId];
    }];
}


- (void)clearCookies:(CDVInvokedUrlCommand*)command
{
    NSHTTPCookie *cookie;
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    for (cookie in [storage cookies]) {
        [storage deleteCookie:cookie];
    }
    [[NSUserDefaults standardUserDefaults] synchronize];
}

@end
