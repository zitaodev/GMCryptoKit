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
    NSString *randomHexString = [GMUtilities dataToHexString:randomData];
    [logStr appendString:@"\n -------------- 安全随机数 --------------"];
    [logStr appendFormat:@"\n 随机数：%@", randomHexString];
    
    // ---------------------- 2、生成SM2密钥对 ----------------------
    // 2.1 二进制数据的密钥对
    NSArray *keyPairData = [GMSm2Cryptor createSm2DataKeyPair];
    NSData *publicKey = keyPairData[0];
    NSData *privateKey = keyPairData[1];
    
    // 2.2 Hex编码字符串的密钥对
    NSArray *keyPairHex = [GMSm2Cryptor createSm2HexKeyPair];
    NSString *publicKeyHex = keyPairHex[0];
    NSString *privateKeyHex = keyPairHex[1];
    
    [logStr appendString:@"\n -------------- SM2生成密钥对 --------------"];
    [logStr appendFormat:@"\n Hex编码公钥：%@", publicKeyHex];
    [logStr appendFormat:@"\n Hex编码私钥：%@", privateKeyHex];
    [logStr appendFormat:@"\n 二进制数据公钥：%@", publicKey];
    [logStr appendFormat:@"\n 二进制数据私钥：%@", privateKey];
    
    // ---------------------- 3、SM2加密和解密 ----------------------
    [logStr appendString:@"\n -------------- SM2加密和解密 --------------"];
    [logStr appendFormat:@"\n Hex编码公钥：%@", publicKeyHex];
    [logStr appendFormat:@"\n Hex编码私钥：%@", privateKeyHex];
    
    // 3.1 UTF-8编码字符串的加密和解密
    NSString *plaintext = @"hello, world!";
    NSString *base64Ciphertext = [GMSm2Cryptor sm2EncryptText:plaintext withPublicKey:publicKeyHex];
    NSString *decryptedtext = [GMSm2Cryptor sm2DecryptText:base64Ciphertext withPrivateKey:privateKeyHex];
    if ([plaintext isEqualToString:decryptedtext]) {
        [logStr appendString:@"\n UTF-8编码字符串的加密和解密结果：成功"];
    } else {
        [logStr appendString:@"\n UTF-8编码字符串的加密和解密结果：失败"];
    }
    [logStr appendFormat:@"\n UTF-8编码明文：%@", plaintext];
    [logStr appendFormat:@"\n base64编码密文：%@", base64Ciphertext];
    [logStr appendFormat:@"\n base64密文解密结果：%@", decryptedtext];
    
    // 3.2 Hex编码字符串的加密和解密
    NSString *hexPlaintext = [GMUtilities stringToHexString:plaintext];
    NSString *hexCiphertext = [GMSm2Cryptor sm2EncryptHexText:hexPlaintext withPublicKey:publicKeyHex];
    NSString *decryptedHextext = [GMSm2Cryptor sm2DecryptHexText:hexCiphertext withPrivateKey:privateKeyHex];
    if ([hexPlaintext isEqualToString:decryptedHextext]) {
        [logStr appendString:@"\n Hex编码字符串的加密和解密结果：成功"];
    } else {
        [logStr appendString:@"\n Hex编码字符串的加密和解密结果：失败"];
    }
    [logStr appendFormat:@"\n Hex编码明文：%@", hexPlaintext];
    [logStr appendFormat:@"\n Hex编码密文：%@", hexCiphertext];
    [logStr appendFormat:@"\n Hex编码密文解密结果：%@", decryptedHextext];
    
    // 3.3 二进制数据的加密和解密
    NSData *plaintextData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextData = [GMSm2Cryptor sm2EncryptData:plaintextData withPublicKey:publicKey];
    NSData *decryptedData = [GMSm2Cryptor sm2DecryptData:ciphertextData withPrivateKey:privateKey];
    if ([plaintextData isEqualToData:decryptedData]) {
        [logStr appendString:@"\n 二进制数据的加密和解密结果：成功"];
    } else {
        [logStr appendString:@"\n 二进制数据的加密和解密结果：失败"];
    }
    [logStr appendFormat:@"\n 二进制数据明文：%@", plaintextData];
    [logStr appendFormat:@"\n 二进制数据密文：%@", ciphertextData];
    [logStr appendFormat:@"\n 二进制密文解密结果：%@", decryptedData];
    
    // ---------------------- 4、SM2数字签名和验证 ----------------------
    // 4.1 UTF-8编码字符串的签名和验签
    NSString *message = @"hello, world!";
    NSString *base64Signature = [GMSm2Cryptor sm2SignText:message withPrivateKey:privateKeyHex];
    BOOL isBase64SignatureValid = [GMSm2Cryptor sm2VerifyText:base64Signature forMessage:message withPublicKey:publicKeyHex];
    if (isBase64SignatureValid) {
        [logStr appendString:@"\n UTF-8编码字符串的签名和验签结果：成功"];
    } else {
        [logStr appendString:@"\nU TF-8编码字符串的签名和验签结果：失败"];
    }
    [logStr appendFormat:@"\n UTF-8编码待签名消息：%@", message];
    [logStr appendFormat:@"\n base64编码签名结果：%@", base64Signature];
    [logStr appendFormat:@"\n base64编码验签结果：%@", @(isBase64SignatureValid)];
    
    // 4.2 Hex编码字符串的签名和验签
    NSString *hexMessage = [GMUtilities stringToHexString:message];
    NSString *hexSignature = [GMSm2Cryptor sm2SignHexText:hexMessage withPrivateKey:privateKeyHex];
    BOOL isHexSignatureValid = [GMSm2Cryptor sm2VerifyHexText:hexSignature forMessageHex:hexMessage withPublicKey:publicKeyHex];
    if (isHexSignatureValid) {
        [logStr appendString:@"\n Hex编码字符串的签名和验签结果：成功"];
    } else {
        [logStr appendString:@"\n Hex编码字符串的签名和验签结果：失败"];
    }
    [logStr appendFormat:@"\n Hex编码待签名消息：%@", hexMessage];
    [logStr appendFormat:@"\n Hex编码签名结果：%@", hexSignature];
    [logStr appendFormat:@"\n Hex编码验签结果：%@", @(isHexSignatureValid)];
    
    // 4.3 二进制数据的签名和验签
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [GMSm2Cryptor sm2SignData:messageData withPrivateKey:privateKey];
    BOOL isSignatureValid = [GMSm2Cryptor sm2VerifyData:signatureData forMessageData:messageData withPublicKey:publicKey];
    if (isSignatureValid) {
        [logStr appendString:@"\n 二进制数据的签名和验签结果：成功"];
    } else {
        [logStr appendString:@"\n 二进制数据的签名和验签结果：失败"];
    }
    [logStr appendFormat:@"\n 二进制数据待签名消息：%@", messageData];
    [logStr appendFormat:@"\n 二进制数据签名结果：%@", signatureData];
    [logStr appendFormat:@"\n 二进制数据验签结果：%@", @(isSignatureValid)];
    
    // ---------------------- 5、SM3提取摘要 ----------------------
    [logStr appendString:@"\n -------------- SM3提取摘要 --------------"];
    // 5.1 UTF-8编码字符串的摘要提取
    NSString *sm3message = @"hello world!";
    NSString *sm3Digest = [GMSm3Digest sm3DigestWithText:sm3message];
    if (sm3Digest) {
        [logStr appendString:@"\n UTF-8编码字符串的摘要提取结果：成功"];
    }else {
        [logStr appendString:@"\n UTF-8编码字符串的摘要提取结果：失败"];
    }
    [logStr appendFormat:@"\n UTF-8编码消息明文：%@", sm3message];
    [logStr appendFormat:@"\n base64编码摘要结果：%@", sm3Digest];
    // 5.2 Hex编码字符串的摘要提取
    NSString *sm3messageHex = [GMUtilities stringToHexString:sm3message];
    sm3Digest = [GMSm3Digest sm3DigestWithHexText:sm3messageHex];
    if (sm3Digest) {
        [logStr appendString:@"\n Hex编码字符串的摘要提取结果：成功"];
    }else {
        [logStr appendString:@"\n Hex编码字符串的摘要提取结果：失败"];
    }
    [logStr appendFormat:@"\n Hex编码消息明文：%@", sm3messageHex];
    [logStr appendFormat:@"\n Hex编码摘要结果：%@", sm3Digest];
    // 7.3 二进制数据的摘要提取
    NSData *sm3messageData = [GMUtilities stringToData:sm3message];
    NSData *sm3DigestData = [GMSm3Digest sm3DigestWithData:sm3messageData];
    if (sm3DigestData) {
        [logStr appendString:@"\n 二进制数据的摘要提取结果：成功"];
    }else {
        [logStr appendString:@"\n 二进制数据的摘要提取结果：失败"];
    }
    [logStr appendFormat:@"\n 二进制数据消息明文：%@", sm3messageData];
    [logStr appendFormat:@"\n 二进制摘要结果：%@", sm3DigestData];
    
    
    // ---------------------- 6、基于SM3计算HMAC ----------------------
    NSData *hmacKeyData = [GMRandomGenerator secRandomDataWithLength:32];
    NSString *hmacKey = [GMUtilities dataToHexString:hmacKeyData];
    [logStr appendString:@"\n -------------- 基于SM3计算HMAC --------------"];
    
    // 6.1 UTF-8编码字符串的HMAC计算
    NSString *sm3HmacMessage = @"hello, world!";
    NSString *sm3HmacBase64 = [GMSm3Digest hmacSm3DigestWithText:sm3HmacMessage key:hmacKey];
    if (sm3HmacBase64) {
        [logStr appendString:@"\n UTF-8编码字符串的HMAC计算结果：成功"];
    }else {
        [logStr appendString:@"\n UTF-8编码字符串的HMAC计算结果：失败"];
    }
    [logStr appendFormat:@"\n UTF-8编码消息明文：%@", sm3HmacMessage];
    [logStr appendFormat:@"\n HMAC计算Base64结果：%@", sm3HmacBase64];
    // 6.2 Hex编码字符串的HMAC计算
    NSString *sm3HmacMessageHex = [GMUtilities stringToHexString:sm3HmacMessage];
    NSString *sm3HmacHex = [GMSm3Digest hmacSm3DigestWithHexText:sm3HmacMessageHex key:hmacKey];
    if (sm3HmacHex) {
        [logStr appendString:@"\n Hex编码字符串的HMAC计算结果：成功"];
    }else {
        [logStr appendString:@"\n Hex编码字符串的HMAC计算结果：失败"];
    }
    [logStr appendFormat:@"\n Hex编码消息明文：%@", sm3HmacMessageHex];
    [logStr appendFormat:@"\n Hex编码HMAC计算结果：%@", sm3HmacHex];
    // 6.3 二进制数据的HMAC计算
    NSData *sm3HmacMessageData = [GMUtilities stringToData:sm3HmacMessage];
    NSData *hmacData = [GMSm3Digest hmacSm3DigestWithData:sm3HmacMessageData key:hmacKeyData];
    if (hmacData) {
        [logStr appendString:@"\n 二进制数据的HMAC计算成功"];
    }else {
        [logStr appendString:@"\n 二进制数据的HMAC计算失败"];
    }
    [logStr appendFormat:@"\n 二进制数据消息明文：%@", sm3HmacMessageData];
    [logStr appendFormat:@"\n 二进制数据HMAC计算结果：%@", hmacData];
    
    // ---------------------- 7、SM4加密和解密 ----------------------
    // 7.1 生成密钥和初始化向量
    // 7.1.1 二进制数据的密钥和初始化向量
    NSData *sm4KeyData = [GMSm4Cryptor createSm4Key];
    NSData *sm4IvData = [GMSm4Cryptor createSm4Key];
    // 7.1.2 Hex编码字符串的密钥和初始化向量
    NSString *sm4Key = [GMSm4Cryptor createSm4HexKey];
    NSString *sm4Iv = [GMSm4Cryptor createSm4HexKey];
    
    [logStr appendString:@"\n -------------- SM4加密和解密 --------------"];
    [logStr appendFormat:@"\n Hex编码密钥：%@", sm4Key];
    [logStr appendFormat:@"\n Hex编码初始化向量：%@", sm4Iv];
    [logStr appendFormat:@"\n 二进制数据密钥：%@", sm4KeyData];
    [logStr appendFormat:@"\n 二进制数据初始化向量：%@", sm4IvData];
    // 7.2 UTF-8编码字符串的加密和解密
    NSString *sm4Plaintext = @"hello, world!";
    NSString *sm4CiphertextBase64 = [GMSm4Cryptor sm4CbcPaddingEncryptText:sm4Plaintext withKey:sm4Key withIv:sm4Iv];
    NSString *sm4Decryptedtext = [GMSm4Cryptor sm4CbcPaddingDecryptText:sm4CiphertextBase64 withKey:sm4Key withIv:sm4Iv];
    if ([sm4Decryptedtext isEqualToString:sm4Plaintext]) {
        [logStr appendString:@"\n UTF-8编码字符串的加密和解密结果：成功"];
    } else {
        [logStr appendString:@"\n UTF-8编码字符串的加密和解密结果：失败"];
    }
    [logStr appendFormat:@"\n UTF-8编码明文：%@", sm4Plaintext];
    [logStr appendFormat:@"\n base64编码密文：%@", sm4CiphertextBase64];
    [logStr appendFormat:@"\n base64编码密文解密结果：%@", sm4Decryptedtext];
    // 7.3 Hex编码字符串的加密和解密
    NSString *sm4plaintextHex = [GMUtilities stringToHexString:sm4Plaintext];
    NSString *sm4CiphertextHex = [GMSm4Cryptor sm4CbcPaddingEncryptHexText:sm4plaintextHex withKey:sm4Key withIv:sm4Iv];
    NSString *sm4DecryptedtextHex = [GMSm4Cryptor sm4CbcPaddingDecryptHexText:sm4CiphertextHex withKey:sm4Key withIv:sm4Iv];
    if ([sm4DecryptedtextHex isEqualToString:sm4plaintextHex]) {
        [logStr appendString:@"\n Hex编码字符串的加密和解密结果：成功"];
    } else {
        [logStr appendString:@"\n Hex编码字符串的加密和解密结果：失败"];
    }
    [logStr appendFormat:@"\n Hex编码明文：%@", sm4plaintextHex];
    [logStr appendFormat:@"\n Hex编码密文：%@", sm4CiphertextHex];
    [logStr appendFormat:@"\n Hex编码密文解密结果：%@", sm4DecryptedtextHex];
    // 7.4 二进制数据的加密和解密
    NSData *sm4PlaintextData = [GMUtilities stringToData:sm4Plaintext];
    NSData *sm4CiphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:sm4PlaintextData withKey:sm4KeyData withIv:sm4IvData];
    NSData *sm4DecryptedData = [GMSm4Cryptor sm4CbcPaddingDecryptData:sm4CiphertextData withKey:sm4KeyData withIv:sm4IvData];
    if ([sm4DecryptedData isEqualToData:sm4PlaintextData]) {
        [logStr appendString:@"\n 二进制数据的加密和解密结果：成功"];
    } else {
        [logStr appendString:@"\n 二进制数据的加密和解密结果：失败"];
    }
    [logStr appendFormat:@"\n 二进制数据明文：%@", sm4PlaintextData];
    [logStr appendFormat:@"\n 二进制数据密文：%@", sm4CiphertextData];
    [logStr appendFormat:@"\n 二进制数据密文解密结果：%@", sm4DecryptedData];

    NSLog(@"%@", logStr);
}

@end
