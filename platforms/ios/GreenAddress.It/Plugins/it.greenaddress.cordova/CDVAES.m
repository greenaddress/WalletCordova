//
//  CDVAES.m
//  GreenAddress.It
//

#import "CDVAES.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>

@implementation CDVAES

- (void)encrypt:(CDVInvokedUrlCommand*)command
{
    NSString* dataString = [command.arguments objectAtIndex:0];
    NSMutableData* data = [[dataString dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    
    // ISO 10126 padding
    NSMutableData* paddingMinusSize = [NSMutableData dataWithLength:15 - (data.length % 16)];
    if (paddingMinusSize.length) {
        SecRandomCopyBytes(NULL, paddingMinusSize.length, paddingMinusSize.mutableBytes);
        [data appendData:paddingMinusSize];
    }
    const unsigned char paddingSize = paddingMinusSize.length + 1;
    [data appendBytes:&paddingSize length:1];
    
    NSString* password = [command.arguments objectAtIndex:1];
    
    NSMutableData* salt = [NSMutableData dataWithLength:16];
    SecRandomCopyBytes(NULL, 16, salt.mutableBytes);

    NSData* key = [CDVAES AESKeyForPassword:password salt:salt];
    
    size_t outLength;
    NSMutableData* cipherData = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
    
    CCCryptorStatus result = CCCrypt(kCCEncrypt, // operation
                     kCCAlgorithmAES, // Algorithm
                     0, // options
                     key.bytes, // key
                     key.length, // keylength
                     salt.bytes, // iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     cipherData.mutableBytes, // dataOut
                     cipherData.length, // dataOutAvailable
                     &outLength); // dataOutMoved

    CDVPluginResult *pluginResult;
    if (result == kCCSuccess) {
        cipherData.length = outLength;
        [salt appendData:cipherData];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                         messageAsString:[salt base64Encoding]];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                         messageAsString:@"Encryption error"];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)decrypt:(CDVInvokedUrlCommand*)command
{
    NSString* dataString = [command.arguments objectAtIndex:0];
    NSData* data = [[NSData alloc] initWithBase64Encoding:dataString];
    
    NSString* password = [command.arguments objectAtIndex:1];
    
    NSData* salt = [data subdataWithRange:NSMakeRange(0, 16)];
    data = [data subdataWithRange:NSMakeRange(16, data.length-16)];
    
    NSData* key = [CDVAES AESKeyForPassword:password salt:salt];
    
    size_t outLength;
    NSMutableData* cipherData = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
    
    CCCryptorStatus result = CCCrypt(kCCDecrypt, // operation
                                     kCCAlgorithmAES, // Algorithm
                                     0, // options
                                     key.bytes, // key
                                     key.length, // keylength
                                     salt.bytes, // iv
                                     data.bytes, // dataIn
                                     data.length, // dataInLength,
                                     cipherData.mutableBytes, // dataOut
                                     cipherData.length, // dataOutAvailable
                                     &outLength); // dataOutMoved
    
    CDVPluginResult *pluginResult;
    if (result == kCCSuccess) {
        const unsigned char* outBytes = cipherData.bytes;
        cipherData.length = outLength;
        cipherData.length -= outBytes[outLength-1];
        NSString* result = [[NSString alloc] initWithData:cipherData
                                                 encoding:NSUTF8StringEncoding];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                         messageAsString:result];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                         messageAsString:@"Encryption error"];
    }
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    
}

+ (NSData *)AESKeyForPassword:(NSString *)password
                         salt:(NSData *)salt {
    NSMutableData* derivedKey = [NSMutableData dataWithLength:kCCKeySizeAES256];
    
    int result = CCKeyDerivationPBKDF(kCCPBKDF2,            // algorithm
                                  password.UTF8String,  // password
                                  [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding],  // passwordLength
                                  salt.bytes,           // salt
                                  salt.length,          // saltLen
                                  kCCPRFHmacAlgSHA1,    // PRF
                                  10,         // rounds
                                  derivedKey.mutableBytes, // derivedKey
                                  derivedKey.length); // derivedKeyLen
    
    // Do not log password here
    NSAssert(result == kCCSuccess,
             @"Unable to create AES key for password: %d", result);
    
    return derivedKey;
}

@end
