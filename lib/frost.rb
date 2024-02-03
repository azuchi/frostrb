# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa'
require 'securerandom'

module FROST
  class Error < StandardError; end

  autoload :SecretShare, "frost/secret_share"
  autoload :Polynomial, "frost/polynomial"
  autoload :SigningKey, "frost/signing_key"

end
