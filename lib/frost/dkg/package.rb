module FROST
  module DKG
    class Package
      attr_reader :identifier
      attr_reader :commitments
      attr_reader :proof

      # Constructor
      # @param [Integer] identifier
      # @param [Array] commitments The list of commitment.
      # @param [FROST::Signature] proof
      def initialize(identifier, commitments, proof)
        raise ArgumentError, "identifier must be Integer." unless identifier.is_a?(Integer)
        raise ArgumentError, "identifier must be greater than 0." if identifier < 1
        raise ArgumentError, "proof must be FROST::Signature." unless proof.is_a?(FROST::Signature)

        @identifier = identifier
        @commitments = commitments
        @proof = proof
      end

      # Get verification key for this proof.
      # @return [ECDSA::Point]
      def verification_key
        commitments.first
      end
    end
  end
end