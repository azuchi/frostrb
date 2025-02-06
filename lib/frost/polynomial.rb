module FROST

  # Polynomial class.
  class Polynomial
    attr_reader :coefficients
    attr_reader :context

    # Generate polynomial.
    # @param [Array] coefficients Coefficients of polynomial.
    # The first is the constant term, followed by the coefficients in descending order of order.
    # @param [FROST::Context] context
    def initialize(context, coefficients)
      raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
      raise ArgumentError, "coefficients must be an Array." unless coefficients.is_a?(Array)
      raise ArgumentError, "Two or more coefficients are required." if coefficients.length < 2

      @coefficients = coefficients
      @context = context
    end

    # Get group
    # @return [ECDSA::Group]
    def group
      context.group
    end

    # Generate random polynomial using secret as constant term.
    # @param [FROST::Context] context
    # @param [Integer|FROST::SigningKey] secret Secret value as constant term.
    # @param [Integer] degree Degree of polynomial.
    # @return [FROST::Polynomial] Polynomial
    def self.from_secret(context, secret, degree)
      secret = secret.scalar if secret.is_a?(FROST::SigningKey)
      raise ArgumentError, "secret must be Integer." unless secret.is_a?(Integer)
      raise ArgumentError, "degree must be Integer." unless degree.is_a?(Integer)
      raise ArgumentError, "degree must be greater than or equal to 1." if degree < 1
      coeffs = degree.times.map {SecureRandom.random_number(context.group.order - 1)}
      Polynomial.new(context, coeffs.prepend(secret))
    end

    # Generate secret share.
    # @param [Integer] identifier Identifier for evaluating polynomials.
    # @return [FROST::SecretShare] Generate share.
    def gen_share(identifier)
      raise ArgumentError, "identifiers must be Integer." unless identifier.is_a?(Integer)

      return SecretShare.new(context, identifier, 0) if coefficients.empty?
      return SecretShare.new(context, identifier, coefficients.last) if identifier == 0

      # Calculate using Horner's method.
      last = coefficients.last
      (coefficients.length - 2).step(0, -1) do |i|
        tmp = last * identifier
        last = (tmp + coefficients[i]) % group.order
      end
      SecretShare.new(context, identifier, last)
    end

    # Generate coefficient commitments
    # @return [Array] A list of coefficient commitment (ECDSA::Point).
    def gen_commitments
      coefficients.map{|c| group.generator * c }
    end

    # Generate proof of knowledge for secret.
    # @param [Integer] identifier Identifier of the owner of this polynomial.
    # @return [FROST::Signature]
    def gen_proof_of_knowledge(identifier)
      FROST::DKG.gen_proof_of_knowledge(identifier, self)
    end

    # Get secret value in this polynomial.
    # @return [Integer] secret
    def secret
      coefficients.first
    end

    # Get point to correspond to secret in this polynomial.
    # @return [ECDSA::Point] secret point
    def verification_point
      group.generator * secret
    end

    # Generates the lagrange coefficient for the i'th participant.
    # The Lagrange polynomial for a set of points (xj, yj) for 0 <= j <= k is
    # ∑_{i=0}^k yi.ℓi(x), where ℓi(x) is the Lagrange basis polynomial:
    # ℓi(x) = ∏_{0≤j≤k; j≠i} (x - xj) / (xi - xj).
    # This computes ℓj(x) for the set of points `xs` and for the j corresponding to the given xj.
    # @param [Array] x_coordinates The list of x-coordinates.
    # @param [Integer] xi an x-coordinate contained in x_coordinates.
    # @param [ECDSA::Group] group Elliptic curve group.
    # @param [Integer] x (Optional) if x is nil, it uses 0 for it (since Identifiers can't be 0).
    # @return [Integer] The lagrange coefficient.
    def self.derive_interpolating_value(x_coordinates, xi, group, x: nil)
      raise ArgumentError, "xi is not included in x_coordinates." unless x_coordinates.include?(xi)
      raise ArgumentError, "Duplicate values in x_coordinates." if (x_coordinates.length - x_coordinates.uniq.length) > 0
      raise ArgumentError, "group must be ECDSA::Group." unless group.is_a?(ECDSA::Group)
      raise ArgumentError, "x must be Integer." if x && !x.is_a?(Integer)

      field = ECDSA::PrimeField.new(group.order)
      numerator = 1
      denominator = 1

      x_coordinates.each do |xj|
        next if xi == xj
        if x
          numerator *= (x - xj)
          denominator *= (xi - xj)
        else
          numerator *= xj
          denominator *= (xj - xi)
        end
      end

      field.mod(numerator * field.inverse(denominator))
    end
  end

end
