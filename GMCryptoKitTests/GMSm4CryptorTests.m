//
//  GMSm4CryptorTests.m
//  GMCryptoKitTests
//
//  Created by zitaodev's Laptop on 2024/3/26.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "GMSm4Cryptor.h"

@interface GMSm4CryptorTests : XCTestCase

@property (nonatomic, copy) NSData *keyData;  // 密钥
@property (nonatomic, copy) NSData *iVData;   // 初始化向量
@property (nonatomic, copy) NSString *plaintext;   // 预置原文,Base64编码

@end

@implementation GMSm4CryptorTests

- (void)setUp {
    self.keyData = [GMSm4Cryptor createSm4Key];
    self.iVData = [GMSm4Cryptor createSm4Key];
    self.plaintext = @"R01TbTRDcnlwdG9yJkNvcHlyaWdodCDCqSAyMDI0IHppdGFvZGV2LiBBbGwgcmlnaHRzIHJlc2VydmVkLiZHTUNyeXB0b0tpdCAwLjEuMA==";
}

- (void)tearDown {
    self.keyData = nil;
    self.iVData = nil;
    self.plaintext = nil;
}

- (void)testSm4CryptorDecryption {
    NSString *ciphertextBase64Encoded = @"OgaZ/skbF19uODW6WTGbb50kdfa7bdd78hQDF0CqhDcRYdYPI3Q0gvQscw0FgEdH";
    NSData *ciphertextData = [[NSData alloc] initWithBase64EncodedString:ciphertextBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(ciphertextData != nil);
    
    NSString *expectedPlaintextBase64Encoded = @"Q3JlYXRlZCBieSB6aXRhb2RldidzIExhcHRvcCBvbiAyMDI0LzMvMjYu";
    NSData *expectedPlaintextData = [[NSData alloc] initWithBase64EncodedString:expectedPlaintextBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(expectedPlaintextData != nil);
    
    NSString *keyBase64Encoded = @"67WDADP3Bce7tASo8Mprtw==";
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(keyData != nil);
    
    NSString *iVBase64Encoded = @"7z+qWyaaTO+Hfz9nLyUCsA==";
    NSData *iVData = [[NSData alloc] initWithBase64EncodedString:iVBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(iVData != nil);

    NSData *decryptedData = [GMSm4Cryptor sm4CbcPaddingDecryptData:ciphertextData withKey:keyData withIv:iVData];
    XCTAssertNotNil(decryptedData, @"解密结果不能为空");
    XCTAssertEqualObjects(expectedPlaintextData, decryptedData);
}

- (void)testSm4CryptorEncryption {
    NSString *plaintextBase64Encoded = @"R01TbTRDcnlwdG9yJkNvcHlyaWdodCDCqSAyMDI0IHppdGFvZGV2LiBBbGwgcmlnaHRzIHJlc2VydmVkLg==";
    NSData *plaintextData = [[NSData alloc] initWithBase64EncodedString:plaintextBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(plaintextData != nil);
    
    NSString *keyBase64Encoded = @"cIx0P6Nglt7puBLUdzfaHw==";
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(keyData != nil);
    
    NSString *iVBase64Encoded = @"It1hlDUhvRRKYGAQF4ULcA==";
    NSData *iVData = [[NSData alloc] initWithBase64EncodedString:iVBase64Encoded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(iVData != nil);

    NSData *ciphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:plaintextData withKey:keyData withIv:iVData];
    NSData *expectedPlaintextData = [GMSm4Cryptor sm4CbcPaddingDecryptData:ciphertextData withKey:keyData withIv:iVData];
    XCTAssertNotNil(ciphertextData, @"密文不能为空");
    XCTAssertEqualObjects(expectedPlaintextData, plaintextData);
}

- (void)testSm4CryptorCreateSm4Key {
    NSData *keyData = [GMSm4Cryptor createSm4Key];
    NSData *iVData = [GMSm4Cryptor createSm4Key];
    XCTAssertNotNil(keyData, @"生成密钥不能为空");
    XCTAssertTrue((keyData.length == 16));
    XCTAssertNotNil(iVData, @"生成iv不能为空");
    XCTAssertTrue((iVData.length == 16));
}

- (void)testSm4CryptorThrows {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptData:nil withKey:[NSData data] withIv:[NSData data]]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptData:[NSData data] withKey:nil withIv:[NSData data]]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptData:[NSData data] withKey:[NSData data] withIv:nil]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptData:nil withKey:[NSData data] withIv:[NSData data]]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptData:[NSData data] withKey:nil withIv:[NSData data]]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptData:[NSData data] withKey:[NSData data] withIv:nil]);
    #pragma clang diagnostic pop
}

- (void)testPerformanceSm4Decrypt {
    NSData *plaintextData = [[NSData alloc] initWithBase64EncodedString:self.plaintext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *ciphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:plaintextData withKey:self.keyData withIv:self.iVData];
    assert(ciphertextData != nil);
    [self measureBlock:^{
        NSData *decryptedData = [GMSm4Cryptor sm4CbcPaddingDecryptData:ciphertextData withKey:self.keyData withIv:self.iVData];
        XCTAssertNotNil(decryptedData, @"解密结果不能为空");
    }];
}

- (void)testPerformanceSm4Encrypt {
    NSData *plaintextData = [[NSData alloc] initWithBase64EncodedString:self.plaintext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    assert(plaintextData != nil);
    [self measureBlock:^{
        NSData *ciphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:plaintextData withKey:self.keyData withIv:self.iVData];
        XCTAssertNotNil(ciphertextData, @"密文不能为空");
    }];
}

- (void)testPerformanceSm4KeyGenerate {
    [self measureBlock:^{
        NSData *keyData = [GMSm4Cryptor createSm4Key];
        NSData *iVData = [GMSm4Cryptor createSm4Key];
        XCTAssertNotNil(keyData, @"生成密钥不能为空");
        XCTAssertNotNil(iVData, @"生成iv不能为空");
    }];
}
@end
