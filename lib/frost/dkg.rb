module FROST
  # Distributed Key Generation feature.
  module DKG

    autoload :Package, "frost/dkg/package"

    module_function

    # Performs the first part of the DKG.
    # Participant generate key and commitments, proof of knowledge for secret.
    # @param [Integer] identifier
    # @param [ECDSA::Group] group Group of elliptic curve.
    # @return [Array] The triple of polynomial and public package(FROST::DKG::Package)
    def part1(identifier, min_signers, max_signers, group)
      raise ArgumentError, "identifier must be Integer" unless identifier.is_a?(Integer)
      raise ArgumentError, "identifier must be greater than 0." if identifier < 1
      raise ArgumentError, "group must be ECDSA::Group." unless group.is_a?(ECDSA::Group)
      raise ArgumentError, "max_signers must be greater than or equal to min_signers." if max_signers < min_signers

      secret = FROST::SigningKey.generate(group)
      # Every participant P_i samples t random values (a_{i0}, ..., a_{i(t−1)}) ← Z_q
      polynomial = secret.gen_poly(min_signers - 1)
      [polynomial, Package.new(identifier, polynomial.gen_commitments, polynomial.gen_proof_of_knowledge(identifier))]
    end

    # Verify proof of knowledge for received commitment.
    # @param [FROST::DKG::Package] package Received package.
    # @return [Boolean]
    def verify_proof_of_knowledge(package)
      verification_key = package.verification_key
      msg = FROST.encode_identifier(package.identifier, verification_key.group) +
        [verification_key.to_hex + package.proof.r.to_hex].pack("H*")
      challenge = Hash.hdkg(msg, verification_key.group)
      package.proof.r == verification_key.group.generator * package.proof.s + (verification_key * challenge).negate
    end
  end
end