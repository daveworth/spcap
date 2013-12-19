# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'spcap/version'

Gem::Specification.new do |spec|
  spec.name          = "spcap"
  spec.version       = Spcap::VERSION
  spec.authors       = ["Bernard Rodier"]
  spec.email         = ["bernard.rodier@gmail.com"]
  spec.description   = %q{Very simple pcap file handler that is not require native extension}
  spec.summary       = %q{Pure ruby gem without native exstension that handle pcap file produce by pcap library or tcpdump}
  spec.homepage      = "https://github.com/brodier/spcap"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "log4r", "~> 1.1.10"
  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
end
