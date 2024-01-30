# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa/ext'

module Frost
  class Error < StandardError; end

  autoload :SigningKey, "frost/signing_key"

end
