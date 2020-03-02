//
//  ViewController.m
//  test
//
//  Created by gongsheng on 2019/8/26.
//  Copyright © 2019 gongsheng. All rights reserved.
//

#import "ViewController.h"
#include <CommonCrypto/CommonDigest.h>
#import "GTMBase64.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self test2];
}

- (void)test2 {
    /*测试链接
     http://yqq.file.mediportal.com.cn/yqq_5b911b43955f06317c6bd792/3974e8eaab11b2dd5b357e60e5a587d1  etag:FtfVrVsdpVf9t_tCfyvsVC-1p6aW
     4M以上文件亲测正确
     */
    
    NSURL *url = [NSURL URLWithString:@"http://yqq.file.mediportal.com.cn/yqq_5b911b43955f06317c6bd792/3974e8eaab11b2dd5b357e60e5a587d1"];
    NSError *error;
    NSData * data = [NSData dataWithContentsOfURL:url options:NSDataReadingMapped error:&error];
    NSString *etag = [self caculateETagWith:data];
    NSLog(@"etag------%@", etag);
}

//算法实现
- (NSString *)caculateETagWith:(NSData *)data
{
    unsigned long blockSize = 4 * 1024 * 1024;
    NSMutableData *sha1Data = [NSMutableData data];
    Byte prefix = 0x16;
    int blockCount = 0;
    
    unsigned long bufferSize = [data length];
    //获取余数
    unsigned long remainder = bufferSize % blockSize;
    //获取商
    double fa = (double)bufferSize / blockSize;
    //向下取整
    blockCount = floor(fa);
    
    if (bufferSize > blockSize) {//大于4M的文件
        NSMutableData *sha2Data = [NSMutableData data];
        for (int i = 0; i < blockCount+1; i++) {
            NSUInteger length = blockSize;
            if (i == blockCount && remainder > 0) {
                length = remainder;
            }
            //将每个块（包括4M块和小于4M的块）进行sha1加密并拼接起来
            NSData *subData = [data subdataWithRange:NSMakeRange(i * blockSize, length)];
            [sha2Data appendData:[self sha1:subData]];
        }
        //将拼接块进行二次sha1加密
        [sha1Data appendData:[self sha1:sha2Data]];
    } else {
        [sha1Data appendData:[self sha1:data]];
    }

    if (!sha1Data.length) return @"Fto5o-5ea0sNMlW_75VgGJCv2AcJ";
    
    NSData *sha1Buffer = sha1Data;
    if (bufferSize > blockSize) {
        //大于4M，头部拼接0x96单个字节
        prefix = 0x96;
    }
    
    Byte preByte[] = {prefix};
    NSMutableData *mutaData = [NSMutableData dataWithBytes:preByte length:1];
    [mutaData appendData:sha1Buffer];
    
    //将长度为21个字节的二进制数据进行url_safe_base64计算
    return [self safeBase64WithSha1Str:mutaData];
}

/*
 sha1加密（加密后的data长度为20）
 */
- (NSData*)sha1:(NSData *)data
{
    //注：如果用以下代码，转换出的data长度为40
//    const char *cstr = [sourceStr cStringUsingEncoding:NSUTF8StringEncoding];
//    NSData *data = [NSData dataWithBytes:cstr length:sourceStr.length];
//    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
//    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
//        [output appendFormat:@"%02x", digest[i]];
//    return output;
    
    //sha1Data长度为20（CC_SHA1_DIGEST_LENGTH系统设定为20）
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    NSData * sha1Data = [[NSData alloc] initWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    return sha1Data;
}

- (NSString *)safeBase64WithSha1Str:(NSData *)base64
{
    //Base64编码中包含有"+,/,="不安全的URL字符串，我们要对这些字符进行转换
    NSString *base64Str = [GTMBase64 encodeBase64Data:base64];

    NSMutableString *safeBase64Str = [[NSMutableString alloc] initWithString:base64Str];

    safeBase64Str = (NSMutableString *)[safeBase64Str stringByReplacingOccurrencesOfString:@"+"withString:@"-"];

    safeBase64Str = (NSMutableString *)[safeBase64Str stringByReplacingOccurrencesOfString:@"/"withString:@"_"];

    safeBase64Str = (NSMutableString *)[safeBase64Str stringByReplacingOccurrencesOfString:@"="withString:@""];
    
    return safeBase64Str;
}

@end
