//
//  HelpfulGlue.m
//  Electron-Cash
//
//  Created by calin on 2/23/18.
//  Copyright © 2018 Calin Culianu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <Python.h>

@interface HelpfulGlue : NSObject {
}
@end

@implementation HelpfulGlue
+ (void) NSLogString:(NSString *)string {
    NSLog(@"%@",string);
}

+ (void) affineScaleView:(UIView *)v scaleX:(CGFloat)scaleX scaleY:(CGFloat)scaleY {
    v.transform = CGAffineTransformMakeScale(scaleX, scaleY);
}
@end

