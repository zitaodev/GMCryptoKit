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
@property (nonatomic, copy) NSString *expectedHmacDigestText;  // 预置hmac摘要,Base64编码
@property (nonatomic, copy) NSString *keyText;                 // 密钥,Base64编码

@end

@implementation GMSm3DigestTests

- (void)setUp {
    self.inputText = @"Copyright © 2024 zitaodev. All rights reserved.";
    self.expectedDigestText = @"JdDMJHzBV5pMiNBjDx7NeCIpY8gFiV7eH/O4rKD5Kv4=";
    self.expectedHmacDigestText = @"FnR4M9589MZZ9A9UUP2bx38ced/1LOKitiswEN3kF8Y=";
    self.keyText = @"lDvrzbpQ1RxSJdKnd0Toz7ouvorO0h4U6vjEfjnxSRA=";
}

- (void)tearDown {
    self.inputText = nil;
    self.expectedDigestText = nil;
}

- (void)testHmacSm3Digest {
    NSData *inputData = [self.inputText dataUsingEncoding:NSUTF8StringEncoding];
    assert(inputData != nil);
    
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:self.keyText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(keyData != nil);
    
    NSData *expectedData = [[NSData alloc] initWithBase64EncodedString:self.expectedHmacDigestText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(expectedData != nil);
    
    NSData *digestData = [GMSm3Digest gm_hmacSm3DigestWithData:inputData keyData:keyData];
    XCTAssertNotNil(digestData, @"hmacSm3摘要值不能为空");
    XCTAssertEqualObjects(expectedData, digestData);
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
    XCTAssertThrows((void) [GMSm3Digest gm_hmacSm3DigestWithData:nil keyData:[NSData data]]);
    XCTAssertThrows((void) [GMSm3Digest gm_hmacSm3DigestWithData:[NSData data] keyData:nil]);
    XCTAssertThrows((void) [GMSm3Digest gm_sm3DigestWithData:nil]);
    XCTAssertThrows((void) [GMSm3Digest gm_sm3DigestWithData:[NSData data]]);
    #pragma clang diagnostic pop
}

- (void)testPerformanceHmacSm3Digest {
    NSData *plaintextData = [self.inputText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:self.keyText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    [self measureBlock:^{
        // 提取摘要
        NSData *digestData = [GMSm3Digest gm_hmacSm3DigestWithData:plaintextData keyData:keyData];
        XCTAssertTrue(digestData,  @"hmacSm3摘要值不能为空");
    }];
}

- (void)testPerformanceSm3Digest {
    NSData *plaintextData = [self.inputText dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        // 提取摘要
        NSData *digestData = [GMSm3Digest gm_sm3DigestWithData:plaintextData];
        XCTAssertTrue(digestData,  @"SM3摘要值不能为空");
    }];
}

@end
