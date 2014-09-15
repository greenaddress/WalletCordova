//
//  CDVECDSA.m
//  GreenAddress
//

#import "CDVECDSA.h"
#import <CoreBitcoin/CoreBitcoin.h>

@implementation CDVECDSA

- (void)sign:(CDVInvokedUrlCommand*)command
{
    NSString* keyWif = [command argumentAtIndex:0];
    NSString* hashHex = [command argumentAtIndex:1];

    BTCKey* key = [[BTCKey alloc] initWithPrivateKeyAddress:[BTCPrivateKeyAddress addressWithBase58String:keyWif]];
    NSData* hash = BTCDataWithHexString(hashHex);
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                      messageAsString:BTCHexStringFromData([key signatureForHash:hash])];
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


@end
