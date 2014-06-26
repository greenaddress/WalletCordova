//
//  CDVBIP39.m
//  GreenAddress.It
//

#import "CDVBIP39.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonKeyDerivation.h>

@implementation CDVBIP39

- (void)calcSeed:(CDVInvokedUrlCommand*)command;
{
    NSString* salt = [command.arguments objectAtIndex:0];
    NSString* password = [command.arguments objectAtIndex:1];
    
    if (salt != nil && password != nil) {
        [self.commandDelegate runInBackground:^{
            NSMutableData *saltData = [[NSMutableData alloc] initWithData:[salt dataUsingEncoding:NSUTF8StringEncoding]];
            // append block index:
            unsigned char blockIndex[4] = {0, 0, 0, 1};
            [saltData appendBytes:blockIndex length:4];
            NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];

            NSMutableData *block =
            [NSMutableData dataWithLength:CC_SHA512_DIGEST_LENGTH];
            
            CCHmac(kCCHmacAlgSHA512, passwordData.bytes, passwordData.length,
                   saltData.bytes, saltData.length, block.mutableBytes);
            
            NSMutableData *u = [block mutableCopy];
            for (int i = 1; i < 2048; i++) {
                NSData *uCopy = [u copy];
                CCHmac(kCCHmacAlgSHA512, passwordData.bytes, passwordData.length,
                       uCopy.bytes, uCopy.length, u.mutableBytes);
                unsigned char* blockBytes = [block mutableBytes];
                const unsigned char* uBytes = [u bytes];
                for (int j = 0; j < block.length; j++) blockBytes[j] ^= uBytes[j];
                int prevProgress = 100*i/2048, curProgress = 100*(i+1)/2048;
                if (curProgress > prevProgress) {
                    CDVPluginResult* progressResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                                           messageAsInt:curProgress];
                    [progressResult setKeepCallbackAsBool:true];
                    [self.commandDelegate sendPluginResult:progressResult callbackId:command.callbackId];
                }
            }
            
            NSMutableArray* result = [[NSMutableArray alloc] init];
            const unsigned char* blockBytes = [block bytes];
            for (int i = 0; i < block.length; i++)
                [result addObject:[[NSNumber alloc] initWithUnsignedChar:blockBytes[i]]];
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                              messageAsArray:result];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        }];

    } else {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:@"Arg was null"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }

}

@end
