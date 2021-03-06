# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ffi/nats/core/version'

Gem::Specification.new do |spec|
  spec.name          = "ffi-nats-core"
  spec.version       = FFI::Nats::Core::VERSION
  spec.authors       = ["Brandon Dewitt"]
  spec.email         = ["brandonsdewitt@gmail.com"]

  spec.summary       = %q{ core ffi bindings for ffi-nats }
  spec.description   = %q{ core ffi bindings for ffi-nats }
  spec.homepage      = "https://www.github.com/abrandoned/ffi-nats-core"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end

  # cnats files
  spec.files         += Dir.glob("vendor/cnats/CMakeLists.txt")
  spec.files         += Dir.glob("vendor/cnats/adapters/**/*")
  spec.files         += Dir.glob("vendor/cnats/src/**/*")
  spec.files         += Dir.glob("vendor/cnats/test/**/*")
  spec.files         += Dir.glob("vendor/cnats/examples/**/*")

  spec.bindir        = "exe"
  spec.extensions    = "ext/ffi/nats/core/Rakefile"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi"

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "pry"
  spec.add_development_dependency "rake", "~> 10.0"
end
