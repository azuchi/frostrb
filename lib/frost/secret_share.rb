module FROST
  # A secret share generated by performing a (t-out-of-n) secret sharing scheme.
  class SecretShare
    attr_reader :identifier
    attr_reader :share

    # Generate secret share.
    # @param [Integer] identifier Identifier of this share.
    # @param [Integer] share A share.
    def initialize(identifier, share)
      raise ArgumentError, "identifier must be Integer." unless identifier.is_a?(Integer)
      raise ArgumentError, "share must be Integer." unless share.is_a?(Integer)

      @identifier = identifier
      @share = share
    end
  end
end
