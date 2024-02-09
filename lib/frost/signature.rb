module FROST
  # A Schnorr signature over some prime order group (or subgroup).
  class Signature
    attr_reader :r
    attr_reader :s

    # Constructor
    # @param [ECDSA::Point] r Public nonce of signature.
    # @param [Integer] s Scalar value of signature.
    def initialize(r, s)
      raise ArgumentError, "r must be ECDSA::Point" unless r.is_a?(ECDSA::Point)
      raise ArgumentError, "s must be Integer" unless s.is_a?(Integer)

      @r = r
      @s = s
    end

    # Encode signature to hex string.
    # @return [String]
    def to_hex
      encode.unpack1("H*")
    end

    # Encode signature to byte string.
    # @return [String]
    def encode
      ECDSA::Format::PointOctetString.encode(r, compression: true) +
        ECDSA::Format::IntegerOctetString.encode(s, 32)
    end
  end
end