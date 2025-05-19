module FROST
  # Dealer
  class Dealer
    attr_reader :ctx
    attr_reader :max_signers
    attr_reader :min_signers
    attr_reader :polynomial

    # Create a new dealer.
    # @param [FROST::Context] ctx FROST context.
    # @param [Integer] max_signers Maximum number of signers.
    # @param [Integer] min_signers Minimum number of signers.
    # @param [Boolean] zero_key If true, generate a refreshing share (i.e. a key with a zero value).
    # @return [FROST::Dealer]
    # @raise [ArgumentError]
    def initialize(ctx, max_signers, min_signers, zero_key: false)
      raise ArgumentError, "context must be FROST::Context." unless ctx.is_a?(FROST::Context)
      raise ArgumentError, "min_signers must be Integer." unless min_signers.is_a?(Integer)
      raise ArgumentError, "min_signers must be greater than 1." if min_signers < 2
      raise ArgumentError, "max_signers must be Integer." unless max_signers.is_a?(Integer)
      raise ArgumentError, "max_signers must be greater than or equal to min_signers." if max_signers < min_signers
      @ctx = ctx
      @min_signers = min_signers
      @max_signers = max_signers
      key = zero_key ? SigningKey.new(ctx, 0, allow_zero_key: true) : SigningKey.generate(ctx)
      @polynomial = key.gen_poly(min_signers - 1)
    end

    # Generate shares.
    # @return [Array] Array of shares(FROST::SecretShare).
    # @raise [ArgumentError]
    def gen_shares(identifiers = nil)
      raise ArgumentError, "identifiers must be Array." if identifiers && !identifiers.is_a?(Array)
      identifiers = if identifiers
                      identifiers.each do |id|
                        raise ArgumentError, "identifier must be Integer." unless id.is_a?(Integer)
                        raise ArgumentError, "identifier must be greater than 0." if id < 1
                      end
                      identifiers
                    else
                      (1..max_signers).to_a
                    end
      identifiers.map{ |i| polynomial.gen_share(i) }
    end

    # Get a group public key.
    # @return [ECDSA::Point]
    def group_public_key
      polynomial.verification_point
    end
  end
end