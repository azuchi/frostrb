# frozen_string_literal: true

require_relative "lib/frost/version"

Gem::Specification.new do |spec|
  spec.name = "frost-ruby"
  spec.version = FROST::VERSION
  spec.authors = ["azuchi"]
  spec.email = ["azuchi@chaintope.com"]

  spec.summary = "Ruby implementations of Two-Round Threshold Schnorr Signatures with FROST."
  spec.description = spec.summary
  spec.homepage = "https://github.com/azuchi/frostrb"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  spec.add_dependency "ecdsa_ext", "~> 0.5.0"
  spec.add_dependency "h2c", "~> 0.2.1"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
