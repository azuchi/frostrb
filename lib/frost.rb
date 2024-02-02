# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa'
require 'securerandom'

module FROST
  class Error < StandardError; end

  autoload :Polynomial, "frost/polynomial"
  autoload :SigningKey, "frost/signing_key"

end
