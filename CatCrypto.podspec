#
# Be sure to run `pod lib lint CatCrypto.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'CatCrypto'
  s.version          = '0.1.2'
  s.summary          = 'An easy way for hashing, support Argon2 currently.'
  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC
  s.homepage         = 'https://github.com/ImKcat/CatCrypto'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Kcat' => 'kcatdeveloper@icloud.com' }
  s.source           = { :git => 'https://github.com/ImKcat/CatCrypto.git', :tag => s.version.to_s }
  s.social_media_url = 'https://imkcat.com'

  s.ios.deployment_target = '8.0'
  s.source_files = 'CatCrypto/**/*.{h,c,modulemap,swift}'
  s.private_header_files = 'CatCrypto/Argon2/*.h'

  s.preserve_paths = 'CatCrypto/Argon2/module.modulemap'
  s.pod_target_xcconfig= {
    'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/CatCrypto/Argon2'
  }
  s.requires_arc = true
end
