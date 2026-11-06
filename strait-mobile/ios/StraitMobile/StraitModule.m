#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

// Same JS surface as android/.../StraitModule.kt (NativeModules.Strait + "StraitStatus" events).
@interface RCT_EXTERN_MODULE (Strait, RCTEventEmitter)

RCT_EXTERN_METHOD(start : (NSDictionary *)options resolver : (RCTPromiseResolveBlock)resolve rejecter : (RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(stop : (RCTPromiseResolveBlock)resolve rejecter : (RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(getStatus : (RCTPromiseResolveBlock)resolve rejecter : (RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(checkNetwork : (NSDictionary *)options resolver : (RCTPromiseResolveBlock)resolve rejecter : (RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(generateKey : (RCTPromiseResolveBlock)resolve rejecter : (RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(probeServices : (NSArray *)ids signals : (NSArray *)signals resolver : (RCTPromiseResolveBlock)resolve rejecter : (RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
