//
//  CDVBIP32.m
//  GreenAddress.It
//

#import "CDVBIP32.h"
#import <CoreBitcoin/CoreBitcoin.h>

@implementation CDVBIP32

- (void)seedToKey:(CDVInvokedUrlCommand*)command
{
    CDVPluginResult* pluginResult;
    NSString* seedHex = [command argumentAtIndex:0];
    if (seedHex != nil) {
        BTCKeychain* hdwallet = [[BTCKeychain alloc] initWithSeed:BTCDataWithHexString(seedHex)];
        NSData* priv = [[hdwallet rootKey] privateKey];
        NSData* pub = [[hdwallet rootKey] publicKey];
        NSData* chainCode = [hdwallet chainCode];
        NSArray* result = [NSArray arrayWithObjects:
                           BTCHexStringFromData(priv),
                           BTCHexStringFromData(pub),
                           BTCHexStringFromData(chainCode), nil];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                         messageAsArray:result];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                         messageAsString:@"Arg was null"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    
}

- (void)derive:(CDVInvokedUrlCommand*)command
{
    CDVPluginResult* pluginResult;
    NSString* parentHex = [command argumentAtIndex:0];
    NSNumber* i = [command argumentAtIndex:1];
    NSString* hardenedStr = [command argumentAtIndex:2];
    if (parentHex != nil && i != nil && hardenedStr != nil) {
        BTCKeychain* hdwallet = [[BTCKeychain alloc] initWithExtendedKey:BTCDataWithHexString(parentHex)];
        BTCKeychain* child = [hdwallet derivedKeychainAtIndex:[i intValue]
                                                     hardened:[hardenedStr isEqualToString:@"true"]];
        NSData* priv = [[child rootKey] privateKey];
        NSData* pub = [[child rootKey] publicKey];
        NSData* chainCode = [child chainCode];
        NSArray* result = [NSArray arrayWithObjects:
                           priv ? BTCHexStringFromData(priv) : @"",
                           BTCHexStringFromData(pub),
                           BTCHexStringFromData(chainCode), nil];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                          messageAsArray:result];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                         messageAsString:@"Arg was null"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end
