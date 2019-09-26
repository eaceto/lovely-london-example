//
//  Helper.h
//  Lovely-London-Example
//
//  Created by Kimi on 26/09/2019.
//  Copyright © 2019 Auth0. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Helper : NSObject
+ (NSData *)generateRSAPublicKeyWithModulus:(NSData*)modulus exponent:(NSData*)exponent;
@end

NS_ASSUME_NONNULL_END
