module FROST
  # A signing key for a Schnorr signature on a FROST.
  class SigningKey
    attr_reader :scalar
    attr_reader :context

    # Constructor
    # @param [FROST::Context] context Frost context.
    # @param [Integer] scalar secret key value.
    # @param [Boolean] allow_zero_key Allow zero scalar.
    # @raise [ArgumentError]
    def initialize(context, scalar, allow_zero_key: false)
      raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
      raise ArgumentError, "scalar must be integer." unless scalar.is_a?(Integer)
      raise ArgumentError, "Invalid scalar range." if !allow_zero_key && scalar < 1 || context.group.order - 1 < scalar

      @scalar = scalar
      @context = context
    end

    # Get group
    # @return [ECDSA::Group]
    def group
      context.group
    end

    # Generate signing key.
    # @param [FROST::Context] context
    def self.generate(context)
      raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
      scalar = 1 + SecureRandom.random_number(context.group.order - 1)
      key = SigningKey.new(context, scalar)
      if context.taproot? && !key.to_point.y.even?
        self.generate(context)
      else
        key
      end
    end

    # Generate random polynomial using this secret.
    # @param [Integer] degree Degree of polynomial.
    # @return [FROST::Polynomial] A polynomial
    def gen_poly(degree)
      Polynomial.from_secret(context, scalar, degree)
    end

    # Compute public key.
    # @return [ECDSA::Point]
    def to_point
      group.generator * scalar
    end
  end
end
