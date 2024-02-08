# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa_ext'
require 'securerandom'
require 'digest'
require 'h2c'

module FROST
  class Error < StandardError; end

  autoload :Hash, "frost/hash"
  autoload :Nonce, "frost/nonce"
  autoload :SecretShare, "frost/secret_share"
  autoload :Polynomial, "frost/polynomial"
  autoload :SigningKey, "frost/signing_key"

end
