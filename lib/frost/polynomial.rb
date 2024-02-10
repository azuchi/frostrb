module FROST

  # Polynomial class.
  class Polynomial
    attr_reader :coefficients
    attr_reader :group

    # Generate polynomial.
    # @param [Array] coefficients Coefficients of polynomial.
    # The first is the constant term, followed by the coefficients in descending order of order.
    # @param [ECDSA::Group] group
    def initialize(coefficients, group)
      raise ArgumentError, "coefficients must be an Array." unless coefficients.is_a?(Array)
      raise ArgumentError, "group must be ECDSA::Group." unless group.is_a?(ECDSA::Group)
      raise ArgumentError, "Two or more coefficients are required." if coefficients.length < 2

      @coefficients = coefficients
      @group = group
    end

    # Generate random polynomial using secret as constant term.
    # @param [Integer|FROST::SigningKey] secret Secret value as constant term.
    # @param [Integer] degree Degree of polynomial.
    # @return [FROST::Polynomial] Polynomial
    def self.from_secret(secret, degree, group)
      secret = secret.scalar if secret.is_a?(FROST::SigningKey)
      raise ArgumentError, "secret must be Integer." unless secret.is_a?(Integer)
      raise ArgumentError, "degree must be Integer." unless degree.is_a?(Integer)
      raise ArgumentError, "degree must be greater than or equal to 1." if degree < 1
      coeffs = degree.times.map {SecureRandom.random_number(group.order - 1)}
      Polynomial.new(coeffs.prepend(secret), group)
    end

    # Generate secret share.
    # @param [Integer] identifier Identifier for evaluating polynomials.
    # @return [FROST::SecretShare] Generate share.
    def gen_share(identifier)
      raise ArgumentError, "identifiers must be Integer." unless identifier.is_a?(Integer)

      return SecretShare.new(identifier, 0, group) if coefficients.empty?
      return SecretShare.new(identifier, coefficients.last, group) if identifier == 0

      # Calculate using Horner's method.
      last = coefficients.last
      (coefficients.length - 2).step(0, -1) do |i|
        tmp = last * identifier
        last = (tmp + coefficients[i]) % group.order
      end
      SecretShare.new(identifier, last, group)
    end

    # Generates the lagrange coefficient for the i'th participant.
    # @param [Array] x_coordinates The list of x-coordinates.
    # @param [Integer] xi an x-coordinate contained in x_coordinates.
    # @param [ECDSA::Group] group Elliptic curve group.
    # @return [Integer] The lagrange coefficient.
    def self.derive_interpolating_value(x_coordinates, xi, group)
      raise ArgumentError, "xi is not included in x_coordinates." unless x_coordinates.include?(xi)
      raise ArgumentError, "Duplicate values in x_coordinates." if (x_coordinates.length - x_coordinates.uniq.length) > 0
      raise ArgumentError, "group must be ECDSA::Group." unless group.is_a?(ECDSA::Group)

      field = ECDSA::PrimeField.new(group.order)
      numerator = 1
      denominator = 1
      x_coordinates.each do |xj|
        next if xi == xj
        numerator *= xj
        denominator *= (xj - xi)
      end

      field.mod(numerator * field.inverse(denominator))
    end
  end

end
