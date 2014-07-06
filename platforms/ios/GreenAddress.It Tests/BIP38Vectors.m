//
//  GreenAddress_It_Tests.m
//  GreenAddress.It Tests
//


#import <XCTest/XCTest.h>
#import <CoreBitcoin/BTCData.h>
#import "bip38.h"

@interface BIP38Vectors : XCTestCase

@end

@implementation BIP38Vectors

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample
{
    // invalid password
    NSError *error;
    XCTAssertNil([bip38 decode:@"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq"
                  withPassword:@"ihsotaS"
                         error:&error]);
    XCTAssertEqualObjects([error domain], @"invalid_passphrase");

    // invalid key
    XCTAssertNil([bip38 decode:@"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR" // not BIP38
                  withPassword:@"Satoshi"
                         error:&error]);
    XCTAssertEqualObjects([error domain], @"invalid_privkey");
    
    error = nil;
    XCTAssertNil([bip38 decode:@"asdfghjkl" // not b58check
                  withPassword:@"Satoshi"
                         error:&error]);
    XCTAssertEqualObjects([error domain], @"invalid_privkey");

    // no ecmultiply
    NSString* noecvectors[] = {
        // no compression
        @"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
        @"TestingOneTwoThree",
        @"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
        
        @"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
        @"Satoshi",
        @"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
        
        // compression
        @"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
        @"TestingOneTwoThree",
        @"L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
        
        @"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
        @"Satoshi",
        @"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7"
    };
    
    for (int i = 0; i < sizeof noecvectors/sizeof *noecvectors/3; ++i) {
        XCTAssertEqualObjects([bip38 decode:noecvectors[3*i]
                               withPassword:noecvectors[3*i+1]
                                      error:nil],
                              noecvectors[3*i+2]);
        
        XCTAssertEqualObjects([bip38 encode:noecvectors[3*i+2]
                               withPassword:noecvectors[3*i+1]],
                              noecvectors[3*i]);
    }
    
    // ecmultiply
    NSString* ecvectors[] = {
        @"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
        @"TestingOneTwoThree",
        @"5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2",
        
        @"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
        @"Satoshi",
        @"5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH",
        
        @"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
        @"MOLON LABE",
        @"5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8"
    };
    
    for (int i = 0; i < sizeof ecvectors/sizeof *ecvectors/3; ++i) {
        XCTAssertEqualObjects([bip38 decode:ecvectors[3*i]
                               withPassword:ecvectors[3*i+1]
                                      error:nil],
                              ecvectors[3*i+2]);
    }
    
}

@end
