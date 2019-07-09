# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rack/protection/maximum_cookie/version'

Gem::Specification.new do |spec|
  spec.name          = 'rack-protection-maximum_cookie'
  spec.version       = Rack::Protection::MaximumCookie::VERSION
  spec.authors       = ['Mike Pastore']
  spec.email         = ['mike@oobak.org']

  spec.summary       = %q{Properly enforce cookie limits in Rack responses}
  spec.homepage      = 'https://github.com/mwpastore/rack-protection-maximum_cookie#readme'
  spec.license       = 'MIT'

  spec.files         = %x{git ls-files -z}.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = %w[lib]

  spec.required_ruby_version = '>= 2.1.10'

  spec.add_dependency 'public_suffix', '>= 3.0', '< 5'
  spec.add_dependency 'rack', ENV.fetch('RACK_VERSION', ['>= 1.4.7', '< 2.1'])

  spec.add_development_dependency 'bundler', '>= 1.15', '< 3'
  spec.add_development_dependency 'minitest', '~> 5.0'
  spec.add_development_dependency 'rack-test', '>= 0.7.0', '< 2'
  spec.add_development_dependency 'rake', '~> 12.0'
end
