#
# Be sure to run `pod lib lint CatCrypto.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'CatCrypto'
  s.version          = '0.1.0'
  s.summary          = 'An easy way for crypto.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC

  s.homepage         = 'https://github.com/ImKcat/CatCrypto'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Kcat' => 'kcatdeveloper@icloud.com' }
  s.source           = { :git => 'https://github.com/ImKcat/CatCrypto.git', :tag => s.version.to_s }
  s.social_media_url = 'https://imkcat.com'

  s.ios.deployment_target = '8.0'
  s.source_files = 'Sources/**/*.{h,c,modulemap,swift}'
  s.private_header_files = 'Sources/Argon2/*.h'

  s.preserve_paths = 'Sources/Argon2/module.modulemap'
  s.pod_target_xcconfig= {
    'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/Sources/Argon2'
  }
  s.requires_arc = true
end
