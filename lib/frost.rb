# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa/ext'

module FROST
  class Error < StandardError; end

  autoload :SigningKey, "frost/signing_key"

end
