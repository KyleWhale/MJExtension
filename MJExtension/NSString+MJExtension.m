//
//  NSString+MJExtension.m
//  MJExtensionExample
//
//  Created by MJ Lee on 15/6/7.
//  Copyright (c) 2015年 小码哥. All rights reserved.
//

#import "NSString+MJExtension.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@implementation NSString (MJExtension)

- (NSString *)mj_string {
    
    if (self.length == 0) return self;
    const char *string = [self UTF8String];
    unsigned char cString[CC_MD5_DIGEST_LENGTH];
    CC_MD5( string, (CC_LONG)strlen(string), cString);
    NSMutableString *cStringLower = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i ++) {
        [cStringLower appendFormat:@"%02x", cString[i]];
    }
    return cStringLower;
}

- (NSString *)mj_underlineFromCamel
{
    if (self.length == 0) return self;
    NSMutableString *string = [NSMutableString string];
    for (NSUInteger i = 0; i<self.length; i++) {
        unichar c = [self characterAtIndex:i];
        NSString *cString = [NSString stringWithFormat:@"%c", c];
        NSString *cStringLower = [cString lowercaseString];
        if ([cString isEqualToString:cStringLower]) {
            [string appendString:cStringLower];
        } else {
            [string appendString:@"_"];
            [string appendString:cStringLower];
        }
    }
    return string;
}

- (NSString *)mj_camelFromUnderline
{
    if (self.length == 0) return self;
    NSMutableString *string = [NSMutableString string];
    NSArray *cmps = [self componentsSeparatedByString:@"_"];
    for (NSUInteger i = 0; i<cmps.count; i++) {
        NSString *cmp = cmps[i];
        if (i && cmp.length) {
            [string appendString:[NSString stringWithFormat:@"%c", [cmp characterAtIndex:0]].uppercaseString];
            if (cmp.length >= 2) [string appendString:[cmp substringFromIndex:1]];
        } else {
            [string appendString:cmp];
        }
    }
    return string;
}

- (NSString *)mj_firstCharLower:(NSString *)string
{
    if (self.length == 0) return self;
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key = [string dataUsingEncoding:NSUTF8StringEncoding];

    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    NSMutableData *mutableData = [NSMutableData dataWithLength:kCCKeySizeAES128];
    [mutableData replaceBytesInRange:NSMakeRange(0, key.length) withBytes:key.bytes];
    // do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          [mutableData bytes],   // Key
                                          [key length],          // kCCKeySizeAES
                                          NULL,                  // IV
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        NSData *result = [NSData dataWithBytes:buffer length:encryptedSize];
        free(buffer);
        return [result base64EncodedStringWithOptions:0];
    }
    else {
        free(buffer);
        return nil;
    }
}

- (NSString *)mj_firstCharUpper:(NSString *)string
{
    if (self.length == 0) return self;
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:0];
    NSData *key = [string dataUsingEncoding:NSUTF8StringEncoding];
    // setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    NSMutableData *mutableData = [NSMutableData dataWithLength:kCCKeySizeAES128];
    [mutableData replaceBytesInRange:NSMakeRange(0, key.length) withBytes:key.bytes];
    
    // do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          [mutableData bytes],  // Key
                                          kCCKeySizeAES128,     // kCCKeySizeAES
                                          NULL,                 // IV
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        NSData *result = [NSData dataWithBytes:buffer length:encryptedSize];
        free(buffer);
        return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    }
    else {
        free(buffer);
        return nil;
    }
}

- (BOOL)mj_isPureInt
{
    NSScanner *scan = [NSScanner scannerWithString:self];
    int val;
    return [scan scanInt:&val] && [scan isAtEnd];
}

- (NSURL *)mj_url
{
//    [self stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet characterSetWithCharactersInString:@"!$&'()*+,-./:;=?@_~%#[]"]];
#pragma clang diagnostic push
#pragma clang diagnostic ignored"-Wdeprecated-declarations"
    return [NSURL URLWithString:(NSString *)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (CFStringRef)self, (CFStringRef)@"!$&'()*+,-./:;=?@_~%#[]", NULL,kCFStringEncodingUTF8))];
#pragma clang diagnostic pop
}
@end
