# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa'

module FROST
  class Error < StandardError; end

  autoload :SigningKey, "frost/signing_key"

end
