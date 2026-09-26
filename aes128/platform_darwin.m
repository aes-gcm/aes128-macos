#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <ServiceManagement/ServiceManagement.h>
#include <string.h>

int aesKeychain(unsigned char *key) {
 @autoreleasepool {
  NSDictionary *query=@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService:@"com.aes128.vpn.storage",(__bridge id)kSecAttrAccount:@"encryption-key"};
  NSMutableDictionary *read=[query mutableCopy];read[(__bridge id)kSecReturnData]=@YES;
  CFTypeRef result=NULL;OSStatus status=SecItemCopyMatching((__bridge CFDictionaryRef)read,&result);
  if(status==errSecSuccess){
   NSData *data=(__bridge NSData*)result;
   if(data.length!=32){CFRelease(result);return errSecDecode;}
   memcpy(key,data.bytes,32);CFRelease(result);return 0;
  }
  if(status!=errSecItemNotFound)return status;
  unsigned char fresh[32];status=SecRandomCopyBytes(kSecRandomDefault,32,fresh);if(status)return status;
  NSMutableDictionary *add=[query mutableCopy];
  add[(__bridge id)kSecValueData]=[NSData dataWithBytes:fresh length:32];
  add[(__bridge id)kSecAttrAccessible]=(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
  status=SecItemAdd((__bridge CFDictionaryRef)add,NULL);
  if(status==errSecDuplicateItem)return aesKeychain(key);
  if(status==errSecSuccess)memcpy(key,fresh,32);
  memset(fresh,0,32);return status;
 }
}
char *aesRegisterHelper(void) {
 @autoreleasepool {
  SMAppService *service=[SMAppService daemonServiceWithPlistName:@"com.aes128.vpn.helper.plist"];
  if(service.status==SMAppServiceStatusEnabled)return NULL;
  NSError *error=nil;
  if(service.status!=SMAppServiceStatusRequiresApproval) [service registerAndReturnError:&error];
  if(service.status==SMAppServiceStatusRequiresApproval){
   [SMAppService openSystemSettingsLoginItems];
   return strdup("Allow AES128 VPN in System Settings > General > Login Items & Extensions, then connect again.");
  }
  return error?strdup(error.localizedDescription.UTF8String):NULL;
 }
}
char *aesAutoStart(int enabled) {
 @autoreleasepool {NSError *error=nil;SMAppService *s=SMAppService.mainAppService;
  if(enabled && s.status!=SMAppServiceStatusEnabled)[s registerAndReturnError:&error];
  if(!enabled && s.status!=SMAppServiceStatusNotRegistered)[s unregisterAndReturnError:&error];
  return error?strdup(error.localizedDescription.UTF8String):NULL;
 }
}
int aesAutoStartStatus(void){return SMAppService.mainAppService.status==SMAppServiceStatusEnabled;}
char *aesUnregisterHelper(void) {
 @autoreleasepool {NSError *error=nil;[[SMAppService daemonServiceWithPlistName:@"com.aes128.vpn.helper.plist"] unregisterAndReturnError:&error];return error?strdup(error.localizedDescription.UTF8String):NULL;}
}
