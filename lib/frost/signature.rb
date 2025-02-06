module FROST
  # A Schnorr signature over some prime order group (or subgroup).
  class Signature
    attr_reader :r
    attr_reader :s
    attr_reader :context

    # Constructor
    # @param [FROST::Context] context
    # @param [ECDSA::Point] r Public nonce of signature.
    # @param [Integer] s Scalar value of signature.
    def initialize(context, r, s)
      raise ArgumentError, "r must be ECDSA::Point" unless r.is_a?(ECDSA::Point)
      raise ArgumentError, "s must be Integer" unless s.is_a?(Integer)
      raise ArgumentError, "context must be FROST::Context" unless context.is_a?(FROST::Context)

      @r = r
      @s = s
      @context = context
    end

    # Encode signature to hex string.
    # @return [String]
    def to_hex
      encode.unpack1("H*")
    end

    # Encode signature to byte string.
    # @return [String]
    def encode
      if context.taproot?
        ECDSA::Format::IntegerOctetString.encode(r.x, context.group.byte_length) +
          ECDSA::Format::IntegerOctetString.encode(s, context.group.byte_length)
      else
        ECDSA::Format::PointOctetString.encode(r, compression: true) +
          ECDSA::Format::IntegerOctetString.encode(s, context.group.byte_length)
      end
    end

    # Decode hex value to FROST::Signature.
    # @param [FROST::Context] context
    # @param [String] hex_value Hex value of signature.
    # @return [FROST::Signature]
    # @raise [ArgumentError]
    def self.decode(context, hex_value)
      raise ArgumentError, "context must be FROST::Context" unless context.is_a?(FROST::Context)
      raise ArgumentError, "hex value must be String" unless hex_value.is_a?(String)

      data = [hex_value].pack("H*")
      r_value = if context.taproot?
                  ['02'].pack('C') + data[0...32]
                else
                  data[0...(context.group.byte_length + 1)]
                end
      r = ECDSA::Format::PointOctetString.decode(r_value, context.group)
      s = ECDSA::Format::IntegerOctetString.decode(data[r_value.bytesize..-1])
      Signature.new(context, r, s)
    end
  end
end