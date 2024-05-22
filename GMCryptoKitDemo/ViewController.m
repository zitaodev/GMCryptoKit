//
//  ViewController.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/14.
//

#import "ViewController.h"
#import <GMCryptoKit/GMCryptoKit.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    
    NSMutableString *logStr = [NSMutableString stringWithString:@""];
    // ---------------------- 1、生成随机数 ----------------------
    NSData *randomData = [GMRandomGenerator secRandomDataWithLength:16];
    [logStr appendString:@"\n-------安全随机数-------"];
    [logStr appendFormat:@"\n随机数：%@", randomData];
    
    // ---------------------- 2、生成SM2密钥对 ----------------------
    // 2.1 二进制数据的密钥对
    NSArray *keyPairData = [GMSm2Cryptor createSm2DataKeyPair];
    NSData *publicKey = keyPairData[0];
    NSData *privateKey = keyPairData[1];
    
    // 2.2 Hex编码字符串的密钥对
    NSArray *keyPairHex = [GMSm2Cryptor createSm2HexKeyPair];
    NSString *publicKeyHex = keyPairHex[0];
    NSString *privateKeyHex = keyPairHex[1];
    
    [logStr appendString:@"\n-------SM2密钥对-------"];
    [logStr appendFormat:@"\nHex公钥：%@", publicKeyHex];
    [logStr appendFormat:@"\nHex私钥：%@", privateKeyHex];
    [logStr appendFormat:@"\n公钥：%@", publicKey];
    [logStr appendFormat:@"\n私钥：%@", privateKey];
    
    // ---------------------- 3、SM2加密和解密 ----------------------
    NSString *plaintext = @"hello, world!";
    [logStr appendString:@"\n-------SM2加密和解密-------"];
    [logStr appendFormat:@"\nSM2明文：%@", plaintext];
    [logStr appendFormat:@"\nSM2 Hex公钥：%@", publicKeyHex];
    [logStr appendFormat:@"\nSM2 Hex私钥：%@", privateKeyHex];
    
    // 3.1 UTF-8编码字符串的加密和解密
    NSString *base64Ciphertext = [GMSm2Cryptor sm2EncryptText:plaintext withPublicKey:publicKeyHex];
    NSString *decryptedtext = [GMSm2Cryptor sm2DecryptText:base64Ciphertext withPrivateKey:privateKeyHex];
    if ([plaintext isEqualToString:decryptedtext]) {
        [logStr appendString:@"\n-------SM2 UTF-8编码字符串的加密和解密成功-------"];
    } else {
        [logStr appendString:@"\n-------SM2 UTF-8编码字符串的加密和解密失败-------"];
    }
    [logStr appendFormat:@"\nSM2 Base64编码密文：%@", base64Ciphertext];
    [logStr appendFormat:@"\nSM2 Base64密文解密结果：%@", decryptedtext];
    
    // 3.2 Hex编码字符串的加密和解密
    NSString *hexPlaintext = [GMUtilities stringToHexString:plaintext];
    NSString *hexCiphertext = [GMSm2Cryptor sm2EncryptHexText:hexPlaintext withPublicKey:publicKeyHex];
    NSString *decryptedHextext = [GMSm2Cryptor sm2DecryptHexText:hexCiphertext withPrivateKey:privateKeyHex];
    if ([hexPlaintext isEqualToString:decryptedHextext]) {
        [logStr appendString:@"\n-------SM2 Hex编码字符串的加密和解密成功-------"];
    } else {
        [logStr appendString:@"\n-------SM2 Hex编码字符串的加密和解密失败-------"];
    }
    [logStr appendFormat:@"\nSM2 Hex编码密文：%@", hexCiphertext];
    [logStr appendFormat:@"\nSM2 Hex密文解密结果：%@", decryptedHextext];
    
    // 3.3 二进制数据的加密和解密
    NSData *plaintextData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextData = [GMSm2Cryptor sm2EncryptData:plaintextData withPublicKey:publicKey];
    NSData *decryptedData = [GMSm2Cryptor sm2DecryptData:ciphertextData withPrivateKey:privateKey];
    if ([plaintextData isEqualToData:decryptedData]) {
        [logStr appendString:@"\n-------SM2 二进制数据的加密和解密成功-------"];
    } else {
        [logStr appendString:@"\n-------SM2 二进制数据的加密和解密失败-------"];
    }
    [logStr appendFormat:@"\nSM2 二进制数据密文：%@", ciphertextData];
    [logStr appendFormat:@"\nSM2 二进制密文解密结果：%@", decryptedData];
    
    // ---------------------- 4、SM2数字签名和验证 ----------------------
    // 4.1 UTF-8编码字符串的签名和验签
    NSString *message = @"hello, world!";
    NSString *base64Signature = [GMSm2Cryptor sm2SignText:message withPrivateKey:privateKeyHex];
    BOOL isBase64SignatureValid = [GMSm2Cryptor sm2VerifyText:base64Signature forMessage:message withPublicKey:publicKeyHex];
    if (isBase64SignatureValid) {
        [logStr appendString:@"\n-------SM2 UTF-8编码字符串的签名和验签成功-------"];
    } else {
        [logStr appendString:@"\n-------SM2 UTF-8编码字符串的签名和验签失败-------"];
    }
    [logStr appendFormat:@"\nSM2 base64编码签名结果：%@", base64Signature];
    [logStr appendFormat:@"\nSM2 base64编码验签结果：%@", @(isBase64SignatureValid)];
    
    // 4.2 Hex编码字符串的签名和验签
    NSString *hexMessage = [GMUtilities stringToHexString:message];
    NSString *hexSignature = [GMSm2Cryptor sm2SignHexText:hexMessage withPrivateKey:privateKeyHex];
    BOOL isHexSignatureValid = [GMSm2Cryptor sm2VerifyHexText:hexSignature forMessageHex:hexMessage withPublicKey:publicKeyHex];
    if (isHexSignatureValid) {
        [logStr appendString:@"\n-------SM2 Hex编码字符串的签名和验签成功-------"];
    } else {
        [logStr appendString:@"\n-------SM2 Hex编码字符串的签名和验签失败-------"];
    }
    [logStr appendFormat:@"\nSM2 Hex编码签名结果：%@", hexSignature];
    [logStr appendFormat:@"\nSM2 Hex编码验签结果：%@", @(isHexSignatureValid)];
    
    // 4.3 二进制数据的签名和验签
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [GMSm2Cryptor sm2SignData:messageData withPrivateKey:privateKey];
    BOOL isSignatureValid = [GMSm2Cryptor sm2VerifyData:signatureData forMessageData:messageData withPublicKey:publicKey];
    if (isSignatureValid) {
        [logStr appendString:@"\n-------SM2 二进制数据的签名和验签成功-------"];
    } else {
        [logStr appendString:@"\n-------SM2 二进制数据的签名和验签失败-------"];
    }
    [logStr appendFormat:@"\nSM2 二进制数据签名结果：%@", signatureData];
    [logStr appendFormat:@"\nSM2 二进制数据验签结果：%@", @(isSignatureValid)];
    
    // ---------------------- 5、SM3提取摘要 ----------------------
    NSString *sm3message = @"hello world!";
    [logStr appendString:@"\n-------SM3提取摘要-------"];
    [logStr appendFormat:@"\nSM3消息明文：%@", sm3message];
    // 5.1 UTF-8编码字符串的摘要提取
    NSString *sm3Digest = [GMSm3Digest sm3DigestWithText:sm3message];
    if (sm3Digest) {
        [logStr appendString:@"\n-------SM3 UTF-8编码字符串的摘要提取成功-------"];
    }else {
        [logStr appendString:@"\n-------SM3 UTF-8编码字符串的摘要提取失败-------"];
    }
    [logStr appendFormat:@"\nSM3 Base64编码摘要结果：%@", sm3Digest];
    // 5.2 Hex编码字符串的摘要提取
    NSString *sm3messageHex = [GMUtilities stringToHexString:sm3message];
    sm3Digest = [GMSm3Digest sm3DigestWithHexText:sm3messageHex];
    if (sm3Digest) {
        [logStr appendString:@"\n-------SM3 Hex编码字符串的摘要提取成功-------"];
    }else {
        [logStr appendString:@"\n-------SM3 Hex编码字符串的摘要提取失败-------"];
    }
    [logStr appendFormat:@"\nSM3 Hex编码摘要结果：%@", sm3Digest];
    // 7.3 二进制数据的摘要提取
    NSData *sm3messageData = [GMUtilities stringToData:sm3message];
    NSData *sm3DigestData = [GMSm3Digest sm3DigestWithData:sm3messageData];
    if (sm3DigestData) {
        [logStr appendString:@"\n-------SM3 二进制数据的摘要提取成功-------"];
    }else {
        [logStr appendString:@"\n-------SM3 二进制数据的摘要提取失败-------"];
    }
    [logStr appendFormat:@"\nSM3 二进制摘要结果：%@", sm3DigestData];
    
    
    // ---------------------- 6、基于SM3计算HMAC ----------------------
    NSString *sm3HmacMessage = @"hello, world!";
    NSData *hmacKeyData = [GMRandomGenerator secRandomDataWithLength:32];
    NSString *hmacKey = [GMUtilities dataToHexString:hmacKeyData];
    [logStr appendString:@"\n-------基于SM3计算HMAC-------"];
    [logStr appendFormat:@"\nhmacSm3消息明文：%@", sm3HmacMessage];
    // 6.1 UTF-8编码字符串的HMAC计算
    NSString *sm3Hmac = [GMSm3Digest hmacSm3DigestWithText:sm3HmacMessage key:hmacKey];
    if (sm3Hmac) {
        [logStr appendString:@"\n-------SM3 UTF-8编码字符串的HMAC计算成功-------"];
    }else {
        [logStr appendString:@"\n-------SM3 UTF-8编码字符串的HMAC计算失败-------"];
    }
    [logStr appendFormat:@"\nSM3 HMAC计算Base64结果：%@", sm3Hmac];
    // 6.2 Hex编码字符串的HMAC计算
    NSString *sm3HmacMessageHex = [GMUtilities stringToHexString:sm3HmacMessage];
    sm3Hmac = [GMSm3Digest hmacSm3DigestWithHexText:sm3HmacMessageHex key:hmacKey];
    if (sm3Hmac) {
        [logStr appendString:@"\n-------SM3 Hex编码字符串的HMAC计算成功-------"];
    }else {
        [logStr appendString:@"\n-------SM3 Hex编码字符串的HMAC计算失败-------"];
    }
    [logStr appendFormat:@"\nSM3 HMAC计算Hex结果：%@", sm3Hmac];
    // 6.3 二进制数据的HMAC计算
    NSData *sm3HmacMessageData = [GMUtilities stringToData:sm3HmacMessage];
    NSData *hmacData = [GMSm3Digest hmacSm3DigestWithData:sm3HmacMessageData key:hmacKeyData];
    if (hmacData) {
        [logStr appendString:@"\n-------SM3 二进制数据的HMAC计算成功-------"];
    }else {
        [logStr appendString:@"\n-------SM3 二进制数据的HMAC计算失败-------"];
    }
    [logStr appendFormat:@"\nSM3 HMAC计算二进制结果：%@", hmacData];
    
    // ---------------------- 7、SM4加密和解密 ----------------------
    // 7.1 生成密钥和初始化向量
    // 7.1.1 二进制数据的密钥和初始化向量
    NSData *sm4KeyData = [GMSm4Cryptor createSm4Key];
    NSData *sm4IvData = [GMSm4Cryptor createSm4Key];
    // 7.1.2 Hex编码字符串的密钥和初始化向量
    NSString *sm4Key = [GMSm4Cryptor createSm4HexKey];
    NSString *sm4Iv = [GMSm4Cryptor createSm4HexKey];
    
    NSString *sm4Plaintext = @"hello, world!";
    [logStr appendString:@"\n-------SM4加密和解密-------"];
    [logStr appendFormat:@"\nSM4明文：%@", sm4Plaintext];
    [logStr appendFormat:@"\nSM4密钥：%@", sm4Key];
    [logStr appendFormat:@"\nSM4初始化向量：%@", sm4Iv];
    // 7.2 UTF-8编码字符串的加密和解密
    NSString *sm4Ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptText:sm4Plaintext withKey:sm4Key withIv:sm4Iv];
    NSString *sm4Decryptedtext = [GMSm4Cryptor sm4CbcPaddingDecryptText:sm4Ciphertext withKey:sm4Key withIv:sm4Iv];
    if ([sm4Decryptedtext isEqualToString:sm4Plaintext]) {
        [logStr appendString:@"\n-------SM4 UTF-8编码字符串的加密和解密成功-------"];
    } else {
        [logStr appendString:@"\n-------SM4 UTF-8编码字符串的加密和解密失败-------"];
    }
    [logStr appendFormat:@"\nSM4 Base64编码密文：%@", sm4Ciphertext];
    [logStr appendFormat:@"\nSM4 Base64编码密文解密结果：%@", sm4Decryptedtext];
    // 7.3 Hex编码字符串的加密和解密
    NSString *sm4plaintextHex = [GMUtilities stringToHexString:sm4Plaintext];
    sm4Ciphertext = [GMSm4Cryptor sm4CbcPaddingEncryptHexText:sm4plaintextHex withKey:sm4Key withIv:sm4Iv];
    sm4Decryptedtext = [GMSm4Cryptor sm4CbcPaddingDecryptHexText:sm4Ciphertext withKey:sm4Key withIv:sm4Iv];
    if ([sm4Decryptedtext isEqualToString:sm4plaintextHex]) {
        [logStr appendString:@"\n-------SM4 Hex编码字符串的加密和解密成功-------"];
    } else {
        [logStr appendString:@"\n-------SM4 Hex编码字符串的加密和解密失败-------"];
    }
    [logStr appendFormat:@"\nSM4 Hex编码密文：%@", sm4Ciphertext];
    [logStr appendFormat:@"\nSM4 Hex编码密文解密结果：%@", sm4Decryptedtext];
    // 7.4 二进制数据的加密和解密
    NSData *sm4PlaintextData = [GMUtilities stringToData:sm4Plaintext];
    NSData *sm4CiphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:sm4PlaintextData withKey:sm4KeyData withIv:sm4IvData];
    NSData *sm4DecryptedData = [GMSm4Cryptor sm4CbcPaddingDecryptData:sm4CiphertextData withKey:sm4KeyData withIv:sm4IvData];
    if ([sm4DecryptedData isEqualToData:sm4PlaintextData]) {
        [logStr appendString:@"\n-------SM4 二进制数据的加密和解密成功-------"];
    } else {
        [logStr appendString:@"\n-------SM4 二进制数据的加密和解密失败-------"];
    }
    [logStr appendFormat:@"\nSM4 二进制数据密文：%@", sm4CiphertextData];
    [logStr appendFormat:@"\nSM4 二进制数据密文解密结果：%@", sm4DecryptedData];

    NSLog(@"%@", logStr);
}

@end
