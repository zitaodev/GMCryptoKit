//
//  GMSm3DigestTests.m
//  GMCryptoKitTests
//
//  Created by Joe's Laptop on 2024/3/20.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "GMCryptoKit.h"

@interface GMSm3DigestTests : XCTestCase

@property (nonatomic, copy) NSString *inputText;           // 预置原文,UTF8编码
@property (nonatomic, copy) NSString *expectedDigestText;  // 预置摘要,Base64编码
@end

@implementation GMSm3DigestTests

- (void)setUp {
    self.inputText = @"Copyright © 2024 zitaodev. All rights reserved.";
    self.expectedDigestText = @"JdDMJHzBV5pMiNBjDx7NeCIpY8gFiV7eH/O4rKD5Kv4=";
}

- (void)tearDown {
    self.inputText = nil;
    self.expectedDigestText = nil;
}

- (void)testSm3Digest {
    NSData *inputData = [self.inputText dataUsingEncoding:NSUTF8StringEncoding];
    assert(inputData != nil);
    
    NSData *expectedData = [[NSData alloc] initWithBase64EncodedString:self.expectedDigestText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(expectedData != nil);
    
    NSData *digestData = [GMSm3Digest gm_sm3DigestWithData:inputData];
    XCTAssertNotNil(digestData, @"SM3摘要值不能为空");
    XCTAssertEqualObjects(expectedData, digestData);
}

- (void)testSm3DigestThrows {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertThrows((void) [GMSm3Digest gm_sm3DigestWithData:nil]);
    XCTAssertThrows((void) [GMSm3Digest gm_sm3DigestWithData:[NSData data]]);
    #pragma clang diagnostic pop
}

@end
