//
//  CDVECDSA.m
//  GreenAddress
//

#import "CDVECDSA.h"
#import "libsecp256k1/include/secp256k1.h"
#import "CoreBitcoin/BTCAddress.h"
#import "CoreBitcoin/BTCData.h"
#import "CoreBitcoin/BTCKey.h"

@implementation CDVECDSA

- (void)sign:(CDVInvokedUrlCommand*)command
{
    NSString* keyWif = [command argumentAtIndex:0];
    NSString* hashHex = [command argumentAtIndex:1];

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_signature sig;
    NSData* hash = BTCDataWithHexString(hashHex);
    BTCKey* key = [[BTCKey alloc] initWithPrivateKeyAddress:[BTCPrivateKeyAddress addressWithString:keyWif]];

    int res = secp256k1_ecdsa_sign(ctx, &sig, [hash bytes], [[key privateKey] bytes], NULL, NULL);
    unsigned char der[73];
    size_t outputlen = 73;
    secp256k1_ecdsa_signature_serialize_der(ctx, der, &outputlen, &sig);
    
    CDVPluginResult* pluginResult =
        [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                          messageAsString:BTCHexStringFromData([[NSData alloc] initWithBytes:der length:outputlen])];
    
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


@end
