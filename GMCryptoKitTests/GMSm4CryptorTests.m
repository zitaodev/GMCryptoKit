//
//  GMSm4CryptorTests.m
//  GMCryptoKitTests
//
//  Created by zitaodev's Laptop on 2024/3/26.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "GMCryptoKit.h"

@interface GMSm4CryptorTests : XCTestCase

@property (nonatomic, copy) NSData *keyData;  // 密钥
@property (nonatomic, copy) NSData *iVData;   // 初始化向量
@property (nonatomic, copy) NSString *plaintext;   // 预置原文,UTF-8编码编码
@property (nonatomic, copy) NSString *keyHex;  // hex编码密钥
@property (nonatomic, copy) NSString *ivHex;   // hex编码初始化向量
@end

@implementation GMSm4CryptorTests

- (void)setUp {
    self.keyData = [GMSm4Cryptor createSm4Key];
    self.iVData = [GMSm4Cryptor createSm4Key];
    self.keyHex = [GMSm4Cryptor createSm4HexKey];
    self.ivHex = [GMSm4Cryptor createSm4HexKey];
    self.plaintext = @"Copyright © 2024 zitaodev. All rights reserved.";
}

- (void)tearDown {
    self.keyData = nil;
    self.iVData = nil;
    self.plaintext = nil;
}

- (void)testSm4CbcPaddingDecryptText {
    NSString *ciphertext = @"OgaZ/skbF19uODW6WTGbb50kdfa7bdd78hQDF0CqhDcRYdYPI3Q0gvQscw0FgEdH";
    NSString *expectedPlaintext = @"Created by zitaodev's Laptop on 2024/3/26.";
    NSString *key = @"EBB5830033F705C7BBB404A8F0CA6BB7";
    NSString *iV = @"EF3FAA5B269A4CEF877F3F672F2502B0";
    NSString *decryptedText = [GMSm4Cryptor sm4CbcPaddingDecryptText:ciphertext withKey:key withIv:iV];
    XCTAssertNotNil(decryptedText, @"解密结果不能为空");
    XCTAssertEqualObjects(expectedPlaintext, decryptedText);
}

- (void)testSm4CbcPaddingDecryptHexText {
    NSString *ciphertext = @"3A0699FEC91B175F6E3835BA59319B6F9D2475F6BB6DD77BF214031740AA84371161D60F23743482F42C730D05804747";
    NSString *expectedPlaintext = @"43726561746564206279207A6974616F6465762773204C6170746F70206F6E20323032342F332F32362E";
    NSString *key = @"EBB5830033F705C7BBB404A8F0CA6BB7";
    NSString *iV = @"EF3FAA5B269A4CEF877F3F672F2502B0";
    NSString *decryptedText = [GMSm4Cryptor sm4CbcPaddingDecryptHexText:ciphertext withKey:key withIv:iV];
    XCTAssertNotNil(decryptedText, @"解密结果不能为空");
    XCTAssertEqualObjects(expectedPlaintext, decryptedText);
}

- (void)testSm4CbcPaddingDecryptData {
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

- (void)testSm4CbcPaddingEncryptText {
    NSString *plaintext = @"GMSm4Cryptor&Copyright © 2024 zitaodev. All rights reserved.";
    NSString *key = @"708C743FA36096DEE9B812D47737DA1F";
    NSString *iV = @"22DD61943521BD144A60601017850B70";
    NSString *ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptText:plaintext withKey:key withIv:iV];
    NSString *expectedPlaintext = [GMSm4Cryptor sm4CbcPaddingDecryptText:ciphertext withKey:key withIv:iV];
    XCTAssertNotNil(ciphertext, @"密文不能为空");
    XCTAssertEqualObjects(expectedPlaintext, plaintext);
}

- (void)testSm4CbcPaddingEncryptHexText {
    NSString *plaintext = @"474D536D3443727970746F7226436F7079726967687420C2A92032303234207A6974616F6465762E20416C6C207269676874732072657365727665642E";
    NSString *key = @"708C743FA36096DEE9B812D47737DA1F";
    NSString *iV = @"22DD61943521BD144A60601017850B70";
    NSString *ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptHexText:plaintext withKey:key withIv:iV];
    NSString *expectedPlaintext = [GMSm4Cryptor sm4CbcPaddingDecryptHexText:ciphertext withKey:key withIv:iV];
    XCTAssertNotNil(ciphertext, @"密文不能为空");
    XCTAssertEqualObjects(expectedPlaintext, plaintext);
}

- (void)testSm4CbcPaddingEncryptData {
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

- (void)testSm4CryptorCreateSm4KeyHex {
    NSString *key = [GMSm4Cryptor createSm4HexKey];
    NSString *iV = [GMSm4Cryptor createSm4HexKey];
    XCTAssertNotNil(key, @"生成密钥不能为空");
    XCTAssertTrue((key.length == 32));
    XCTAssertNotNil(iV, @"生成iv不能为空");
    XCTAssertTrue((iV.length == 32));
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
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptText:nil withKey:@"" withIv:@""]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptText:@"" withKey:nil withIv:@""]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptText:@"" withKey:@"" withIv:nil]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptHexText:nil withKey:@"" withIv:@""]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptHexText:@"" withKey:nil withIv:@""]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptHexText:@"" withKey:@"" withIv:nil]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptData:nil withKey:[NSData data] withIv:[NSData data]]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptData:[NSData data] withKey:nil withIv:[NSData data]]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingDecryptData:[NSData data] withKey:[NSData data] withIv:nil]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptText:nil withKey:@"" withIv:@""]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptText:@"" withKey:nil withIv:@""]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptText:@"" withKey:@"" withIv:nil]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptHexText:nil withKey:@"" withIv:@""]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptHexText:@"" withKey:nil withIv:@""]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptHexText:@"" withKey:@"" withIv:nil]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptData:nil withKey:[NSData data] withIv:[NSData data]]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptData:[NSData data] withKey:nil withIv:[NSData data]]);
    XCTAssertThrows((void) [GMSm4Cryptor sm4CbcPaddingEncryptData:[NSData data] withKey:[NSData data] withIv:nil]);
    #pragma clang diagnostic pop
}

- (void)testPerformanceSm4DecryptText {
    NSString *ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptText:self.plaintext withKey:self.keyHex withIv:self.ivHex];
    assert(ciphertext != nil);
    [self measureBlock:^{
        NSString *decryptedText = [GMSm4Cryptor sm4CbcPaddingDecryptText:ciphertext withKey:self.keyHex withIv:self.ivHex];
        XCTAssertNotNil(decryptedText, @"解密结果不能为空");
    }];
}

- (void)testPerformanceSm4DecryptHexText {
    NSString *plaintext = [GMUtilities stringToHexString:self.plaintext];
    assert(plaintext != nil);
    NSString *ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptHexText:plaintext withKey:self.keyHex withIv:self.ivHex];
    assert(ciphertext != nil);
    [self measureBlock:^{
        NSString *decryptedText = [GMSm4Cryptor sm4CbcPaddingDecryptHexText:ciphertext withKey:self.keyHex withIv:self.ivHex];
        XCTAssertNotNil(decryptedText, @"解密结果不能为空");
    }];
}

- (void)testPerformanceSm4DecryptData {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    assert(plaintextData != nil);
    NSData *ciphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:plaintextData withKey:self.keyData withIv:self.iVData];
    assert(ciphertextData != nil);
    [self measureBlock:^{
        NSData *decryptedData = [GMSm4Cryptor sm4CbcPaddingDecryptData:ciphertextData withKey:self.keyData withIv:self.iVData];
        XCTAssertNotNil(decryptedData, @"解密结果不能为空");
    }];
}

- (void)testPerformanceSm4EncryptText {
    [self measureBlock:^{
        NSString *ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptText:self.plaintext withKey:self.keyHex withIv:self.ivHex];
        XCTAssertNotNil(ciphertext, @"密文不能为空");
    }];
}

- (void)testPerformanceSm4EncryptHexText {
    NSString *plaintext = [GMUtilities stringToHexString:self.plaintext];
    assert(plaintext != nil);
    [self measureBlock:^{
        NSString *ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptHexText:plaintext withKey:self.keyHex withIv:self.ivHex];
        XCTAssertNotNil(ciphertext, @"密文不能为空");
    }];
}

- (void)testPerformanceSm4EncryptData {
    NSData *plaintextData = [self.plaintext dataUsingEncoding:NSUTF8StringEncoding];
    assert(plaintextData != nil);
    [self measureBlock:^{
        NSData *ciphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:plaintextData withKey:self.keyData withIv:self.iVData];
        XCTAssertNotNil(ciphertextData, @"密文不能为空");
    }];
}

- (void)testPerformanceSm4HexKeyGenerate {
    [self measureBlock:^{
        NSString *key = [GMSm4Cryptor createSm4HexKey];
        NSString *iV = [GMSm4Cryptor createSm4HexKey];
        XCTAssertNotNil(key, @"生成密钥不能为空");
        XCTAssertNotNil(iV, @"生成iv不能为空");
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
