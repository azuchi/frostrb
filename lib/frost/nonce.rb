module FROST
  class Nonce

    attr_reader :value # nonce value
    attr_reader :context # Group of elliptic curve

    # Generate nonce.
    # @param [FROST::Context] context
    # @param [Integer] nonce
    # @return [FROST::Nonce]
    def initialize(context, nonce)
      raise ArgumentError, "context must be FROST::Context." unless context.is_a?(FROST::Context)
      raise ArgumentError, "nonce must be Integer." unless nonce.is_a?(Integer)
      @value = nonce
      @context = context
    end

    # Get group
    # @return [ECDSA::Group]
    def group
      context.group
    end

    # Generate nonce from secret share.
    # @param [FROST::SigningKey] secret
    def self.gen_from_secret(secret)
      gen_from_random_bytes(secret)
    end

    # Generates a nonce from the given random bytes.
    # This method allows only testing.
    # https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#section-4.1
    # @param [FROST::SigningKey] secret
    # @param [String] random_bytes Random bytes.
    # @return [FROST::Nonce]
    def self.gen_from_random_bytes(secret, random_bytes = SecureRandom.bytes(32))
      secret = secret.to_key if secret.is_a?(SecretShare)
      raise ArgumentError, "secret must be FROST::SigningKey" unless secret.is_a?(FROST::SigningKey)
      raise ArgumentError, "random_bytes must be 32 bytes." unless random_bytes.bytesize == 32

      secret_bytes = ECDSA::Format::IntegerOctetString.encode(secret.scalar, 32)
      msg = random_bytes + secret_bytes
      k = FROST::Hash.h3(msg, secret.context)
      Nonce.new(secret.context, k)
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

    # Generate negated nonce.
    # @return [FROST::Nonce] Negated nonce.
    def to_negate
      Nonce.new(context, group.order - value)
    end

  end
end