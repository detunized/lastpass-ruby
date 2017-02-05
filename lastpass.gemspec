# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

$:.push File.expand_path("../lib", __FILE__)
require "lastpass/version"

Gem::Specification.new do |s|
    s.name        = "lastpass"
    s.version     = LastPass::VERSION
    s.licenses    = ["MIT"]
    s.authors     = ["Dmitry Yakimenko"]
    s.email       = "detunized@gmail.com"
    s.homepage    = "https://github.com/detunized/lastpass-ruby"
    s.summary     = "Unofficial LastPass API"
    s.description = "Read only access to the online LastPass vault"

    s.required_ruby_version = ">= 2.0.0"

    s.add_dependency "httparty", "~> 0.14.0"

    s.add_development_dependency "rake", "~> 12.0"
    s.add_development_dependency "rspec", "~> 3.5"
    s.add_development_dependency "rspec-its", "~> 1.2"
    s.add_development_dependency "coveralls", "~> 0.8.19"

    s.files         = `git ls-files`.split "\n"
    s.test_files    = `git ls-files spec`.split "\n"
    s.require_paths = ["lib"]
end
