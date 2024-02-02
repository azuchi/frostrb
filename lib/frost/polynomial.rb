module FROST

  # Polynomial class.
  class Polynomial
    attr_reader :coefficients
    attr_reader :group

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
  end

end
