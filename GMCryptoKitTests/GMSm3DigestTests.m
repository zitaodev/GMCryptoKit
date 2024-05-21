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
@property (nonatomic, copy) NSString *keyText;                 // 密钥,Hex编码

@end

@implementation GMSm3DigestTests

- (void)setUp {
    self.inputText = @"Copyright © 2024 zitaodev. All rights reserved.";
    self.expectedDigestText = @"JdDMJHzBV5pMiNBjDx7NeCIpY8gFiV7eH/O4rKD5Kv4=";
    self.expectedHmacDigestText = @"FnR4M9589MZZ9A9UUP2bx38ced/1LOKitiswEN3kF8Y=";
    self.keyText = @"943BEBCDBA50D51C5225D2A77744E8CFBA2EBE8ACED21E14EAF8C47E39F14910";
}

- (void)tearDown {
    self.inputText = nil;
    self.expectedDigestText = nil;
}

- (void)testHmacSm3DigestWithText {
    NSString *key = @"7E30ADBCC2F7E17FC166E489774EF11B";
    NSString *expectedText = @"ZQjxkCnjN4pCSC+ImQ0oXI0OjyoyERB0ualwCIZIQwQ=";
    NSString *digestText = [GMSm3Digest hmacSm3DigestWithText:self.inputText key:key];
    XCTAssertNotNil(digestText, @"hmacSm3摘要值不能为空");
    XCTAssertEqualObjects(expectedText, digestText);
}

- (void)testHmacSm3DigestWithHexText {
    NSString *input = @"436F7079726967687420C2A92032303234207A6974616F6465762E20416C6C207269676874732072657365727665642E";
    NSString *key = @"7E30ADBCC2F7E17FC166E489774EF11B";
    NSString *expectedHex = @"6508F19029E3378A42482F88990D285C8D0E8F2A32111074B9A9700886484304";
    NSString *digestHex = [GMSm3Digest hmacSm3DigestWithHexText:input key:key];
    XCTAssertNotNil(digestHex, @"hmacSm3摘要值不能为空");
    XCTAssertEqualObjects(expectedHex, digestHex);
}

- (void)testHmacSm3Digest {
    NSData *inputData = [self.inputText dataUsingEncoding:NSUTF8StringEncoding];
    assert(inputData != nil);
    
    NSData *keyData = [GMUtilities hexStringToData:self.keyText];
    assert(keyData != nil);
    
    NSData *expectedData = [[NSData alloc] initWithBase64EncodedString:self.expectedHmacDigestText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(expectedData != nil);
    
    NSData *digestData = [GMSm3Digest hmacSm3DigestWithData:inputData key:keyData];
    XCTAssertNotNil(digestData, @"hmacSm3摘要值不能为空");
    XCTAssertEqualObjects(expectedData, digestData);
}

- (void)testSm3DigestWithText {
    NSString *expectedtext = @"JdDMJHzBV5pMiNBjDx7NeCIpY8gFiV7eH/O4rKD5Kv4=";
    NSString *digesttext = [GMSm3Digest sm3DigestWithText:self.inputText];
    XCTAssertNotNil(digesttext, @"SM3摘要值不能为空");
    XCTAssertEqualObjects(expectedtext, digesttext);
}

- (void)testSm3DigestWithHexText {
    NSString *inputHex = [GMUtilities stringToHexString:self.inputText];
    assert(inputHex != nil);
    NSString *expectedHex = @"25D0CC247CC1579A4C88D0630F1ECD78222963C805895EDE1FF3B8ACA0F92AFE";
    NSString *digestHex = [GMSm3Digest sm3DigestWithHexText:inputHex];
    XCTAssertNotNil(digestHex, @"SM3摘要值不能为空");
    XCTAssertEqualObjects(expectedHex, digestHex);
}

- (void)testSm3Digest {
    NSData *inputData = [self.inputText dataUsingEncoding:NSUTF8StringEncoding];
    assert(inputData != nil);
    
    NSData *expectedData = [[NSData alloc] initWithBase64EncodedString:self.expectedDigestText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(expectedData != nil);
    
    NSData *digestData = [GMSm3Digest sm3DigestWithData:inputData];
    XCTAssertNotNil(digestData, @"SM3摘要值不能为空");
    XCTAssertEqualObjects(expectedData, digestData);
}

- (void)testSm3DigestThrows {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertThrows((void) [GMSm3Digest hmacSm3DigestWithText:nil key:@""]);
    XCTAssertThrows((void) [GMSm3Digest hmacSm3DigestWithText:@"" key:nil]);
    XCTAssertThrows((void) [GMSm3Digest hmacSm3DigestWithHexText:nil key:@""]);
    XCTAssertThrows((void) [GMSm3Digest hmacSm3DigestWithHexText:@"" key:nil]);
    XCTAssertThrows((void) [GMSm3Digest hmacSm3DigestWithData:nil key:[NSData data]]);
    XCTAssertThrows((void) [GMSm3Digest hmacSm3DigestWithData:[NSData data] key:nil]);
    XCTAssertThrows((void) [GMSm3Digest sm3DigestWithText:nil]);
    XCTAssertThrows((void) [GMSm3Digest sm3DigestWithText:@""]);
    XCTAssertThrows((void) [GMSm3Digest sm3DigestWithHexText:nil]);
    XCTAssertThrows((void) [GMSm3Digest sm3DigestWithHexText:@""]);
    XCTAssertThrows((void) [GMSm3Digest sm3DigestWithData:nil]);
    XCTAssertThrows((void) [GMSm3Digest sm3DigestWithData:[NSData data]]);
    #pragma clang diagnostic pop
}

- (void)testPerformanceHmacSm3DigestWithText {
    [self measureBlock:^{
        // 提取摘要
        NSString *digest = [GMSm3Digest hmacSm3DigestWithText:self.inputText key:self.keyText];
        XCTAssertTrue(digest,  @"hmacSm3摘要值不能为空");
    }];
}

- (void)testPerformanceHmacSm3DigestWithHexText {
    NSString *plaintextHex = [GMUtilities stringToHexString:self.inputText];
    [self measureBlock:^{
        // 提取摘要
        NSString *digest = [GMSm3Digest hmacSm3DigestWithHexText:plaintextHex key:self.keyText];
        XCTAssertTrue(digest,  @"hmacSm3摘要值不能为空");
    }];
}

- (void)testPerformanceHmacSm3DigestWithData {
    NSData *plaintextData = [self.inputText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:self.keyText options:NSDataBase64DecodingIgnoreUnknownCharacters];
    [self measureBlock:^{
        // 提取摘要
        NSData *digestData = [GMSm3Digest hmacSm3DigestWithData:plaintextData key:keyData];
        XCTAssertTrue(digestData,  @"hmacSm3摘要值不能为空");
    }];
}

- (void)testPerformanceSm3DigestWithText {
    [self measureBlock:^{
        // 提取摘要
        NSString *digest = [GMSm3Digest sm3DigestWithText:self.inputText];
        XCTAssertTrue(digest,  @"SM3摘要值不能为空");
    }];
}

- (void)testPerformanceSm3DigestWithHexText {
    NSString *plaintextHex = [GMUtilities stringToHexString:self.inputText];
    [self measureBlock:^{
        // 提取摘要
        NSString *digest = [GMSm3Digest sm3DigestWithHexText:plaintextHex];
        XCTAssertTrue(digest,  @"SM3摘要值不能为空");
    }];
}

- (void)testPerformanceSm3DigestWithData {
    NSData *plaintextData = [self.inputText dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        // 提取摘要
        NSData *digestData = [GMSm3Digest sm3DigestWithData:plaintextData];
        XCTAssertTrue(digestData,  @"SM3摘要值不能为空");
    }];
}

@end
