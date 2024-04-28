//
//  GMSm2Cryptor.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/13.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import "GMSm2Cryptor.h"
#import "GMUtilities.h"
#import <gmssl/sm2.h>

#define GM_CRYPTO_TAG_PUBLICKEY            @"publicKey"
#define GM_CRYPTO_TAG_PRIVATEKEY           @"privateKey"

@implementation GMSm2Cryptor

#pragma mark - SM2 生成密钥对

+ (NSDictionary<NSString *, NSString *> *_Nullable)createSm2Base64KeyPair {
    NSDictionary *keyPairDict = [self createSm2DataKeyPair];
    if (!keyPairDict) {
        return nil;
    }
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    NSString *privateKeyBase64 = [GMUtilities dataToBase64String:keyPairDict[GM_CRYPTO_TAG_PRIVATEKEY]];
    if (privateKeyBase64) {
        dict[GM_CRYPTO_TAG_PRIVATEKEY] = privateKeyBase64;
    }
    NSString *publicKeyBase64 = [GMUtilities dataToBase64String:keyPairDict[GM_CRYPTO_TAG_PUBLICKEY]];
    if (publicKeyBase64) {
        dict[GM_CRYPTO_TAG_PUBLICKEY] = publicKeyBase64;
    }
    return dict;
}

+ (NSDictionary<NSString *, NSString *> *_Nullable)createSm2HexKeyPair {
    NSDictionary *keyPairDict = [self createSm2DataKeyPair];
    if (!keyPairDict) {
        return nil;
    }
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    NSString *privateKeyHexString = [GMUtilities dataToHexString:keyPairDict[GM_CRYPTO_TAG_PRIVATEKEY]];
    if (privateKeyHexString) {
        dict[GM_CRYPTO_TAG_PRIVATEKEY] = privateKeyHexString;
    }
    NSString *publicKeyHexString = [GMUtilities dataToHexString:keyPairDict[GM_CRYPTO_TAG_PUBLICKEY]];
    if (publicKeyHexString) {
        dict[GM_CRYPTO_TAG_PUBLICKEY] = publicKeyHexString;
    }
    return dict;
}

+ (NSDictionary<NSString *, NSData *> *_Nullable)createSm2DataKeyPair {
    return [self createSm2KeyPair];
}

+ (NSDictionary<NSString *, NSData *> *_Nullable)createSm2KeyPair {
    SM2_KEY sm2_key;
    if (sm2_key_generate(&sm2_key) != 1) {
        return nil;
    }
    
    SM2_POINT public_key = sm2_key.public_key;
    size_t pub_key_len = 32 * 2;
    uint8_t pub_key[pub_key_len];
    memcpy(pub_key, public_key.x, 32);
    memcpy(pub_key + 32, public_key.y, 32);
    
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    NSData *privateKey_data = [NSData dataWithBytes:sm2_key.private_key length:32];
    if (privateKey_data) {
        dict[GM_CRYPTO_TAG_PRIVATEKEY] = privateKey_data;
    }
    NSData *publicKey_data = [NSData dataWithBytes:pub_key length:pub_key_len];
    if (publicKey_data) {
        dict[GM_CRYPTO_TAG_PUBLICKEY] = publicKey_data;
    }
    return dict;
}

#pragma mark - SM2 非对称加密算法，加密

+ (NSString *_Nullable)sm2EncryptText:(NSString *)plaintext
                        withPublicKey:(NSString *)publicKey {
    NSData *plaintextData = [GMUtilities stringToData:plaintext];
    NSData *publicKeyData = [GMUtilities hexStringToData:publicKey];
    NSData *cipher_data = [self sm2EncryptData:plaintextData
                                    withPublicKey:publicKeyData];
    return [GMUtilities dataToBase64String:cipher_data];
}

+ (NSString *_Nullable)sm2EncryptHexText:(NSString *)plaintextHex
                           withPublicKey:(NSString *)publicKey {
    NSData *plaintextData = [GMUtilities hexStringToData:plaintextHex];
    NSData *publicKeyData = [GMUtilities hexStringToData:publicKey];
    NSData *cipher_data = [self sm2EncryptData:plaintextData
                                    withPublicKey:publicKeyData];
    return [GMUtilities dataToHexString:cipher_data];
}

+ (NSData *_Nullable)sm2EncryptData:(NSData *)plainData
                         withPublicKey:(NSData *)publicKey {
    NSParameterAssert(plainData != nil);
    NSParameterAssert(plainData.length != 0);
    NSParameterAssert(publicKey != nil);
    NSParameterAssert(publicKey.length == 64);
    
    uint8_t *plaintext_bytes = (uint8_t *)plainData.bytes;
    uint8_t *pub_text = (uint8_t *)publicKey.bytes;
    size_t plaintext_len = plainData.length;
    size_t pub_key_len = publicKey.length;
    
    SM2_POINT sm2_point;
    SM2_KEY sm2_key;
    SM2_CIPHERTEXT ciphertext;
    memcpy(&sm2_point, pub_text, pub_key_len);
    if (sm2_key_set_public_key(&sm2_key, &sm2_point) != 1) {
        return nil;
    }
    
    if (sm2_do_encrypt(&sm2_key, plaintext_bytes, plaintext_len, &ciphertext) != 1) {
        return nil;
    }
    
    size_t c1c3c2_len = 32 * 3 + ((int)ciphertext.ciphertext_size) + 1;
    uint8_t c1c3c2[c1c3c2_len];
    c1c3c2[0] = 0x04;
    memcpy(c1c3c2 + 1, ciphertext.point.x, 32);
    memcpy(c1c3c2 + 1 + 32, ciphertext.point.y, 32);
    memcpy(c1c3c2 + 1 + 32 + 32, ciphertext.hash, 32);
    memcpy(c1c3c2 + 1 + 32 + 32 + 32, ciphertext.ciphertext, ciphertext.ciphertext_size);
    
    NSData *cipher_data = [NSData dataWithBytes:c1c3c2 length:sizeof(c1c3c2)];
    if (!cipher_data || cipher_data.length == 0) {
        return nil;
    }
    return cipher_data;
}

#pragma mark - SM2 非对称加密算法，解密

+ (NSString *_Nullable)sm2DecryptText:(NSString *)ciphertextBase64
                       withPrivateKey:(NSString *)privateKey {
    NSData *cipherData = [GMUtilities base64StringToData:ciphertextBase64];
    NSData *privateKeyData = [GMUtilities hexStringToData:privateKey];
    NSData *plaintext_data = [self sm2DecryptData:cipherData
                                      withPrivateKey:privateKeyData];
    NSString *hexString = [GMUtilities dataToHexString:plaintext_data];
    return [GMUtilities hexStringToString:hexString];
}

+ (NSString *_Nullable)sm2DecryptHexText:(NSString *)ciphertextHex
                          withPrivateKey:(NSString *)privateKey {
    NSData *cipherData = [GMUtilities hexStringToData:ciphertextHex];
    NSData *privateKeyData = [GMUtilities hexStringToData:privateKey];
    NSData *plaintext_data = [self sm2DecryptData:cipherData
                                      withPrivateKey:privateKeyData];
    return [GMUtilities dataToHexString:plaintext_data];
}

+ (NSData *_Nullable)sm2DecryptData:(NSData *)cipherData
                        withPrivateKey:(NSData *)privateKey {
    NSParameterAssert(cipherData != nil);
    NSParameterAssert(cipherData.length > 32 * 3 + 1);
    NSParameterAssert(privateKey != nil);
    NSParameterAssert(privateKey.length == 32);
    
    uint8_t *c1c3c2_bytes = (uint8_t *)cipherData.bytes;
    uint8_t *pri_text = (uint8_t *)privateKey.bytes;
    uint8_t c1c3c2_len = cipherData.length;
    
    SM2_KEY sm2_key;
    u_int8_t private_key[32] = {0};
    memcpy(private_key, pri_text, 32);
    if (sm2_key_set_private_key(&sm2_key,private_key) != 1) {
        return nil;
    }
    
    SM2_CIPHERTEXT ciphertext;
    memcpy(ciphertext.point.x, c1c3c2_bytes + 1, 32);
    memcpy(ciphertext.point.y, c1c3c2_bytes + 32 + 1, 32);
    memcpy(ciphertext.hash, c1c3c2_bytes + 32 + 32 + 1, 32);
    memcpy(ciphertext.ciphertext, c1c3c2_bytes + 32 + 32 + 32 + 1,  c1c3c2_len - 32 * 3 - 1);
    ciphertext.ciphertext_size = c1c3c2_len - 32 * 3 - 1;
    
    uint8_t plaintext_buf[SM2_MAX_PLAINTEXT_SIZE];
    size_t plaintext_len = 0;
    if (sm2_do_decrypt(&sm2_key, &ciphertext, plaintext_buf, &plaintext_len) != 1) {
        return nil;
    }
    
    NSData *original_data = [NSData dataWithBytes:plaintext_buf length:plaintext_len];
    if (!original_data || original_data.length == 0) {
        return nil;
    }
    
    return original_data;
}

#pragma mark - SM2 签名验签算法，签名

+ (NSString *_Nullable)sm2SignText:(NSString *)message
                    withPrivateKey:(NSString *)privateKey {
    NSData *messageData = [GMUtilities stringToData:message];
    NSData *privateKeyData = [GMUtilities hexStringToData:privateKey];
    NSData *signData = [self sm2SignData:messageData withPrivateKey:privateKeyData];
    return [GMUtilities dataToBase64String:signData];
}

+ (NSString *_Nullable)sm2SignHexText:(NSString *)messageHex
                       withPrivateKey:(NSString *)privateKey {
    NSData *messageData = [GMUtilities hexStringToData:messageHex];
    NSData *privateKeyData = [GMUtilities hexStringToData:privateKey];
    NSData *signData = [self sm2SignData:messageData
                             withPrivateKey:privateKeyData];
    return [GMUtilities dataToHexString:signData];
}

+ (NSData *_Nullable)sm2SignData:(NSData *)messageData
                     withPrivateKey:(NSData *)privateKey {
    NSParameterAssert(messageData != nil);
    NSParameterAssert(messageData.length != 0);
    NSParameterAssert(privateKey != nil);
    NSParameterAssert(privateKey.length == 32);
    
    uint8_t *mes_bytes = (uint8_t *)messageData.bytes;
    uint8_t *pri_bytes = (uint8_t *)privateKey.bytes;
    size_t mes_len = messageData.length;
    
    SM2_KEY sm2_key;
    SM2_SIGN_CTX sign_ctx;
    u_int8_t private_key[32];
    memcpy(private_key, pri_bytes, 32);
    if (sm2_key_set_private_key(&sm2_key,private_key) != 1) {
        return nil;
    }
    
    uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
    size_t sig_len;
    if (sm2_sign_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
        || sm2_sign_update(&sign_ctx, mes_bytes, mes_len) != 1
        || sm2_sign_finish(&sign_ctx, sig, &sig_len) != 1) {
        return nil;
    }
    
    SM2_SIGNATURE sig_rs;
    const uint8_t *der = (uint8_t *)sig;
    if (sm2_signature_from_der(&sig_rs, &der, &sig_len) != 1) {
        return nil;
    }
    
    size_t rs_len = 32 * 2;
    uint8_t rs[rs_len];
    memcpy(rs, sig_rs.r, 32);
    memcpy(rs + 32, sig_rs.s, 32);
    
    NSData *rs_data = [NSData dataWithBytes:rs length:rs_len];
    if (!rs_data || rs_data.length == 0) {
        return nil;
    }
    
    return rs_data;
}

#pragma mark - SM2 签名验签算法，验签

+ (BOOL)sm2VerifyText:(NSString *)base64Signature
           forMessage:(NSString *)message
        withPublicKey:(NSString *)publicKey {
    NSData *signatureData = [GMUtilities base64StringToData:base64Signature];
    NSData *messageData = [GMUtilities stringToData:message];
    NSData *publicKeyData = [GMUtilities hexStringToData:publicKey];
    return [self sm2VerifyData:signatureData
                forMessageData:messageData
                 withPublicKey:publicKeyData];
}

+ (BOOL)sm2VerifyHexText:(NSString *)signatureHex
           forMessageHex:(NSString *)messageHex
           withPublicKey:(NSString *)publicKey {
    NSData *signatureData = [GMUtilities hexStringToData:signatureHex];
    NSData *messageData = [GMUtilities hexStringToData:messageHex];
    NSData *publicKeyData = [GMUtilities hexStringToData:publicKey];
    return [self sm2VerifyData:signatureData
                forMessageData:messageData
                withPublicKey:publicKeyData];
}

+ (BOOL)sm2VerifyData:(NSData *)signatureData
       forMessageData:(NSData *)messageData
        withPublicKey:(NSData *)publicKey {
    NSParameterAssert(signatureData != nil);
    NSParameterAssert(signatureData.length == 64);
    NSParameterAssert(messageData != nil);
    NSParameterAssert(messageData.length != 0);
    NSParameterAssert(publicKey != nil);
    NSParameterAssert(publicKey.length == 64);
    
    uint8_t *rs_bytes = (uint8_t *)signatureData.bytes;
    uint8_t *mes_bytes = (uint8_t *)messageData.bytes;
    uint8_t *pub_bytes = (uint8_t *)publicKey.bytes;
    
    size_t rs_len = signatureData.length;
    size_t mes_len = messageData.length;
    size_t pub_key_len = publicKey.length;
    
    SM2_SIGNATURE sig_rs;
    uint8_t der[SM2_MAX_SIGNATURE_SIZE];
    uint8_t *p = (uint8_t *)der;
    size_t der_len = 0;
    memcpy(&sig_rs, rs_bytes, rs_len);
    
    if (sm2_signature_to_der(&sig_rs, &p, &der_len) != 1) {
        return NO;
    }
    
    SM2_KEY sm2_key;
    SM2_POINT point;
    SM2_SIGN_CTX sign_ctx;
    
    memcpy(&point, pub_bytes, pub_key_len);
    if (sm2_key_set_public_key(&sm2_key, &point) != 1) {
        return NO;
    }
    
    if (sm2_verify_init(&sign_ctx, &sm2_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
        || sm2_verify_update(&sign_ctx, mes_bytes, mes_len) != 1
        || sm2_verify_finish(&sign_ctx, der, der_len) != 1) {
        return NO;
    }
    
    return YES;
}

@end
