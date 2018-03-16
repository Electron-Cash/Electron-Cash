//
//  UIViewExtras.h
//  AppVault
//
//  Created by calin on 9/29/09.
//  Copyright 2009 Calin Culianu <calin.culianu@gmail.com>. All rights reserved.
//

#import <UIKit/UIKit.h>


@interface UIView (AnimExtras) 
/// Adds this view to parent view, and slides it into existence from the bottom; makes it the first responder.
- (void) modalSlideFromBottomIntoView:(UIView *)parentView;
/// Identical to above but also with a callback which is called when done.  Callback takes 1 argument, this view itself.
- (void) modalSlideFromBottomIntoView:(UIView *)parentView target:(id)callback_target selector:(SEL)callback;
/// Slides the view out the bottom and removes it from parent when animation is done; resigns first responder.
- (void) modalSlideOutToBottom;
/// Same as above but also with callback when animation is done.  Callback take 1 argument, this UIView itself.
- (void) modalSlideOutToBottomWithTarget:(id)target selector:(SEL)selector;
/// Animate oscillate action -- a good default speed is 10.0
- (void) animateShake:(NSUInteger)nShakes speed:(CGFloat)speed displacement:(CGFloat)disp randPerturbAmount:(CGFloat)pert;
/// Unhides and fades receiver in, fading out `otherView'.  Hides `otherView' when done
- (void) fadeInWhileFadingOutOther:(UIView *)otherView;
/// Renders this entire view to an image, returns the autoreleased image
- (UIImage *) renderToImage;
/// Same as above, but just for a subrect of the view
- (UIImage *) renderToImage:(CGRect)rectInView;
@end

