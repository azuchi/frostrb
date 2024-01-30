module FROST
  # A signing key for a Schnorr signature on a FROST.
  class SigningKey
    attr_reader :scalar
    attr_reader :group

    # Constructor
    # @param [Integer] scalar secret key value.
    # @param [ECDSA::Group] group Group of elliptic curve.
    def initialize(scalar, group = ECDSA::Group::Secp256k1)
      raise ArgumentError, "scalar must be integer." unless scalar.is_a?(Integer)
      raise ArgumentError, "group must be ECDSA::Group." unless group.is_a?(ECDSA::Group)

      @scalar = scalar
      @group = group
    end

    # Generate signing key.
    # @param [ECDSA::Group] group Group of elliptic curve.
    def generate(group = ECDSA::Group::Secp256k1)
      scalar = 1 + SecureRandom.random_number(group.order - 1)
      SigningKey.new(scalar, group)
    end
  end
end
