module FROST
  module DKG
    class PublicPackage
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

      # Verify share.
      # @param [FROST::SecretShare] share
      # @return [Boolean]
      def verify_share(share)
        x = share.identifier
        result = commitments[1..-1].inject(commitments.first) do |sum, com|
          tmp = com * x
          x *= x
          sum + tmp
        end
        result == share.to_point
      end
    end
  end
end