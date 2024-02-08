module FROST
  class Nonce

    attr_reader :value # nonce value
    attr_reader :group # Group of elliptic curve

    # Generate nonce.
    # @return [FROST::Nonce]
    def initialize(nonce, group)
      raise ArgumentError "group must by ECDSA::Group." unless group.is_a?(ECDSA::Group)
      raise ArgumentError "nonce must by Integer." unless nonce.is_a?(Integer)
      @value = nonce
      @group = group
    end

    # Generate nonce from secret share.
    # @param [FROST::SigningKey] secret
    def self.gen_from_secret(secret)
      raise ArgumentError, "secret must be FROST::SigningKey" unless secret.is_a?(FROST::SigningKey)
      Nonce.new(Nonce.gen_from_random_bytes(secret), secret.group)
    end

    # Generates a nonce from the given random bytes.
    # This method allows only testing.
    # https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#section-4.1
    # @param [FROST::SigningKey] secret
    # @param [String] random_bytes Random bytes.
    # @return [FROST::Nonce]
    def self.gen_from_random_bytes(secret, random_bytes = SecureRandom.bytes(32))
      raise ArgumentError, "random_bytes must be 32 bytes." unless random_bytes.bytesize == 32

      secret_bytes = ECDSA::Format::IntegerOctetString.encode(secret.scalar, 32)
      msg = random_bytes + secret_bytes
      nonce = FROST::Hash.h3(msg, secret.group)
      Nonce.new(nonce, secret.group)
    end

    private_class_method :gen_from_random_bytes

    # Convert nonce as hex string.
    # @return [String]
    def to_hex
      ECDSA::Format::IntegerOctetString.encode(value, 32).unpack1('H*')
    end

    # Compute public key.
    # @return [ECDSA::Point]
    def to_point
      group.generator * value
    end

  end
end