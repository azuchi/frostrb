module FROST
  module DKG
    # Package to hold participants' secret share.
    class SecretPackage

      attr_reader :identifier
      attr_reader :polynomial
      attr_reader :public_package
      attr_reader :min_signers
      attr_reader :max_signers

      # Constructor.
      # @param [Integer] identifier The identifier of this owner.
      # @param [Integer] min_signers Minimum number of signers.
      # @param [Integer] max_signers Maximum number of signers.
      # @param [FROST::Polynomial] polynomial Polynomial with secret share.
      def initialize(identifier, min_signers, max_signers, polynomial)
        raise ArgumentError, "identifier must be Integer." unless identifier.is_a?(Integer)
        raise ArgumentError, "identifier must be greater than 0." if identifier < 1
        raise ArgumentError, "min_signers must be Integer." unless min_signers.is_a?(Integer)
        raise ArgumentError, "max_signers must be Integer." unless max_signers.is_a?(Integer)
        raise ArgumentError, "polynomial must be FROST::Polynomial." unless polynomial.is_a?(FROST::Polynomial)
        raise ArgumentError, "max_signers must be greater than or equal to min_signers." if max_signers < min_signers
        raise ArgumentError, "Number of coefficients of polynomial and min_signers do not match." unless min_signers == polynomial.coefficients.length

        @identifier = identifier
        @min_signers = min_signers
        @max_signers = max_signers
        @polynomial = polynomial
        @public_package = Package.new(identifier, polynomial.gen_commitments, polynomial.gen_proof_of_knowledge(identifier))
      end

      # Generate secret share for identifier.
      # @param [Integer] identifier
      # @return [FROST::SecretShare] Generate share.
      def gen_share(identifier)
        polynomial.gen_share(identifier)
      end

      # Get group.
      # @return [ECDSA::Group]
      def group
        polynomial.group
      end

      # Get FROST context.
      # @return [FROST::Context]
      def context
        polynomial.context
      end

      # Get verification point.
      # @return [ECDSA::Point]
      def verification_point
        polynomial.verification_point
      end
    end
  end
end