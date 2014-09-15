//
//  CDVECDSA.h
//  GreenAddress
//

#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface CDVECDSA : CDVPlugin {}

- (void)sign:(CDVInvokedUrlCommand*)command;

@end
