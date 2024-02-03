module FROST

  # Polynomial class.
  class Polynomial
    attr_reader :coefficients
    attr_reader :group

    # Generate polynomial.
    # @param [Array] coefficients Coefficients of polynomial. High order coefficients are first and constant term are last.
    # @param [ECDSA::Group] group
    def initialize(coefficients, group)
      raise ArgumentError, "coefficients must be an Array." unless coefficients.is_a?(Array)
      raise ArgumentError, "group must be ECDSA::Group." unless group.is_a?(ECDSA::Group)
      raise ArgumentError, "Two or more coefficients are required." if coefficients.length < 2

      @coefficients = coefficients
      @group = group
    end

    # Generate random polynomial using secret as constant term.
    # @param [Integer] secret Secret value as constant term.
    # @param [Integer] degree Degree of polynomial.
    # @return [FROST::Polynomial] Polynomial
    def self.from_secret(secret, degree, group)
      raise ArgumentError, "secret must be Integer." unless secret.is_a?(Integer)
      raise ArgumentError, "degree must be Integer." unless degree.is_a?(Integer)
      raise ArgumentError, "degree must be greater than or equal to 1." if degree < 1

      coeffs = degree.times.map {SecureRandom.random_number(group.order - 1)}
      Polynomial.new(coeffs << secret, group)
    end

    # Generate secret share.
    # @param [Integer] identifier Identifier for evaluating polynomials.
    # @return [FROST::SecretShare] Generate share.
    def gen_share(identifier)
      raise ArgumentError, "identifiers must be Integer." unless identifier.is_a?(Integer)

      return SecretShare.new(identifier, 0) if coefficients.empty?
      return SecretShare.new(identifier, coefficients.last) if identifier == 0

      # Calculate using Horner's method.
      coeffs = coefficients.reverse
      last = coeffs.last
      (coeffs.length - 2).step(0, -1) do |i|
        tmp = last * identifier
        last = (tmp + coeffs[i]) % group.order
      end
      SecretShare.new(identifier, last)
    end
  end

end
