//
//  bip38.h
//  bip38
//
//  Copyright (c) 2014 GreenAddress. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface bip38 : NSObject

+ (NSString*) decode:(NSString*)encoded
        withPassword:(NSString*)password
               error:(NSError**)error;

+ (const uint8_t*) _decode_ec:(const uint8_t*)bytes
               password:(NSString*)password
                 hasLot:(bool)hasLot;

+ (NSString*) encode:(NSString*)b58
        withPassword:(NSString*)password;

@end
