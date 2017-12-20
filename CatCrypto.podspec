#
# Be sure to run `pod lib lint CatCrypto.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'CatCrypto'
  s.version          = '0.1.5'
  s.summary          = 'An easy way for hashing.'
 s.description      = <<-DESC
 CatCrypto include a series of hashing functions.
                      DESC
  s.homepage         = 'https://github.com/ImKcat/CatCrypto'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Kcat' => 'kcatdeveloper@icloud.com' }
  s.source           = { :git => 'https://github.com/ImKcat/CatCrypto.git', :tag => s.version.to_s }
  s.social_media_url = 'https://imkcat.com'

  s.ios.deployment_target = '8.0'
  s.osx.deployment_target = '10.10'
  s.tvos.deployment_target = '9.0'
  s.watchos.deployment_target = '2.0'
  
  s.requires_arc = true
  s.source_files = 'CatCrypto/**/*.{h,c,swift}'
  s.private_header_files = ['CatCrypto/MD6/*.h', 'CatCrypto/Argon2/*.h']
  s.preserve_paths = ['CatCrypto/MD6', 'CatCrypto/Argon2', 'CatCrypto/CommonCrypto']
  s.pod_target_xcconfig = {
    'SWIFT_INCLUDE_PATHS[sdk=iphoneos*]'          => '$(PODS_TARGET_SRCROOT)/CatCrypto/CommonCrypto/iPhoneOS $(PODS_TARGET_SRCROOT)/CatCrypto/Argon2 $(PODS_TARGET_SRCROOT)/CatCrypto/MD6',
    'SWIFT_INCLUDE_PATHS[sdk=iphonesimulator*]'   => '$(PODS_TARGET_SRCROOT)/CatCrypto/CommonCrypto/iPhoneSimulator $(PODS_TARGET_SRCROOT)/CatCrypto/Argon2 $(PODS_TARGET_SRCROOT)/CatCrypto/MD6', 
    'SWIFT_INCLUDE_PATHS[sdk=appletvos*]'         => '$(PODS_TARGET_SRCROOT)/CatCrypto/CommonCrypto/AppleTVOS $(PODS_TARGET_SRCROOT)/CatCrypto/Argon2 $(PODS_TARGET_SRCROOT)/CatCrypto/MD6',
    'SWIFT_INCLUDE_PATHS[sdk=appletvsimulator*]'  => '$(PODS_TARGET_SRCROOT)/CatCrypto/CommonCrypto/AppleTVSimulator $(PODS_TARGET_SRCROOT)/CatCrypto/Argon2 $(PODS_TARGET_SRCROOT)/CatCrypto/MD6',
    'SWIFT_INCLUDE_PATHS[sdk=macosx*]'            => '$(PODS_TARGET_SRCROOT)/CatCrypto/CommonCrypto/MacOSX $(PODS_TARGET_SRCROOT)/CatCrypto/Argon2 $(PODS_TARGET_SRCROOT)/CatCrypto/MD6',
    'SWIFT_INCLUDE_PATHS[sdk=watchos*]'           => '$(PODS_TARGET_SRCROOT)/CatCrypto/CommonCrypto/WatchOS $(PODS_TARGET_SRCROOT)/CatCrypto/Argon2 $(PODS_TARGET_SRCROOT)/CatCrypto/MD6',
    'SWIFT_INCLUDE_PATHS[sdk=watchsimulator*]'    => '$(PODS_TARGET_SRCROOT)/CatCrypto/CommonCrypto/WatchSimulator $(PODS_TARGET_SRCROOT)/CatCrypto/Argon2 $(PODS_TARGET_SRCROOT)/CatCrypto/MD6'
  }
end
