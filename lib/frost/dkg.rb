module FROST
  # Distributed Key Generation feature.
  module DKG

    autoload :SecretPackage, "frost/dkg/secret_package"
    autoload :Package, "frost/dkg/package"

    module_function

    # Performs the first part of the DKG.
    # Participant generate key and commitments, proof of knowledge for secret.
    # @param [FROST::Context] context
    # @param [Integer] identifier Party's identifier.
    # @param [Integer] min_signers The number of min signers.
    # @return [FROST::DKG::SecretPackage] Secret received_package for owner.
    def generate_secret(context, identifier, min_signers, max_signers)
      raise ArgumentError, "identifier must be Integer" unless identifier.is_a?(Integer)
      raise ArgumentError, "identifier must be greater than 0." if identifier < 1
      raise ArgumentError, "context must be FROST::Context." unless context.is_a?(FROST::Context)
      raise ArgumentError, "min_signers must be Integer." unless min_signers.is_a?(Integer)
      raise ArgumentError, "max_singers must be Integer." unless max_signers.is_a?(Integer)
      raise ArgumentError, "max_signers must be greater than or equal to min_signers." if max_signers < min_signers

      secret = FROST::SigningKey.generate(context)
      polynomial = secret.gen_poly(min_signers - 1)
      SecretPackage.new(identifier, min_signers, max_signers, polynomial)
    end

    # Generate proof of knowledge for secret.
    # @param [Integer] identifier Identifier of the owner of polynomial.
    # @param [FROST::Polynomial] polynomial Polynomial containing secret.
    # @return [FROST::Signature]
    def gen_proof_of_knowledge(identifier, polynomial)
      raise ArgumentError, "identifier must be Integer." unless identifier.is_a?(Integer)
      raise ArgumentError, "polynomial must be FROST::Polynomial." unless polynomial.is_a?(FROST::Polynomial)

      k = SecureRandom.random_number(polynomial.group.order - 1)
      r = polynomial.group.generator * k
      a0 = polynomial.coefficients.first
      a0_g = polynomial.group.generator * a0
      msg = FROST.encode_identifier(identifier, polynomial.group) + [a0_g.to_hex + r.to_hex].pack("H*")
      challenge = Hash.hdkg(msg, polynomial.context)
      field = ECDSA::PrimeField.new(polynomial.group.order)
      s = field.mod(k + a0 * challenge)
      FROST::Signature.new(polynomial.context, r, s)
    end

    # Verify proof of knowledge for received commitment.
    # @param [FROST::DKG::SecretPackage] secret_package Verifier's secret package.
    # @param [FROST::DKG::Package] received_package Received received_package.
    # @return [Boolean]
    def verify_proof_of_knowledge(secret_package, received_package)
      raise ArgumentError, "secret_package must be FROST::DKG::SecretPackage." unless secret_package.is_a?(FROST::DKG::SecretPackage)
      raise ArgumentError, "received_package must be FROST::DKG::Package." unless received_package.is_a?(FROST::DKG::Package)
      raise FROST::Error, "Invalid number of commitments in package." unless secret_package.min_signers == received_package.commitments.length

      verification_key = received_package.verification_key
      msg = FROST.encode_identifier(received_package.identifier, verification_key.group) +
        [verification_key.to_hex + received_package.proof.r.to_hex].pack("H*")
      challenge = Hash.hdkg(msg, secret_package.polynomial.context)
      received_package.proof.r == verification_key.group.generator * received_package.proof.s + (verification_key * challenge).negate
    end

    # Compute signing share using received shares from other participants.
    #
    # @param [FROST::DKG::SecretPackage] secret_package Own secret received_package.
    # @param [Array] received_packages Array of FROST::DKG::Package received by other participants.
    # @param [Array] received_shares Array of FROST::SecretShare received by other participants.
    # @return [FROST::SecretShare] Signing share.
    # @raise [ArgumentError]
    def compute_signing_share(secret_package, received_packages, received_shares)
      raise ArgumentError, "polynomial must be FROST::DKG::SecretPackage." unless secret_package.is_a?(FROST::DKG::SecretPackage)
      raise FROST::Error, "Invalid number of received_shares." unless secret_package.max_signers - 1 == received_shares.length
      raise ArgumentError, "The number of received_packages and received_shares does not match." unless received_packages.length == received_shares.length

      identifier = received_shares.first.identifier
      signing_share = received_shares.sum {|share| share.share}
      field = ECDSA::PrimeField.new(secret_package.group.order)
      signing_share = field.mod(signing_share + secret_package.gen_share(identifier).share)
      ctx = secret_package.polynomial.context
      if ctx.taproot?
        # Post-process the DKG output. Add an unusable taproot tweak to the group key computed by a DKG run,
        # to prevent peers from inserting rogue tapscript tweaks into the group's joint public key.
        # From BIP-341:
        # > If the spending conditions do not require a script path, the output key should commit to
        # > an unspendable script path instead of having no script path.
        # > This can be achieved by computing the output key  point as Q = P + int(hashTapTweak(bytes(P)))G.
        verification_key = compute_group_pubkey(secret_package, received_packages, apply_even: false)
        has_even = verification_key.y.even?
        unless has_even
          verification_key = verification_key.negate
          signing_share = field.mod(-signing_share)
        end
        signing_share = field.mod(signing_share + tap_tweak(verification_key))
      end
      FROST::SecretShare.new(secret_package.context, identifier, signing_share)
    end

    # Compute Group public key.
    # @param [FROST::DKG::SecretPackage] secret_package Own secret received_package.
    # @param [Array] received_packages Array of FROST::DKG::Package received by other participants.
    # @param [Boolean] apply_even In taproot context, whether tweak to public key or not.
    # @return [ECDSA::Point] Group public key.
    def compute_group_pubkey(secret_package, received_packages, apply_even: true)
      raise ArgumentError, "polynomial must be FROST::DKG::SecretPackage." unless secret_package.is_a?(FROST::DKG::SecretPackage)
      raise FROST::Error, "Invalid number of received_packages." unless secret_package.max_signers - 1 == received_packages.length

      verification_key = received_packages.inject(secret_package.verification_point) {|sum, package| sum + package.commitments.first }
      if secret_package.polynomial.context.taproot? && apply_even
        verification_key = verification_key.negate unless verification_key.y.even?
        verification_key + (verification_key.group.generator * tap_tweak(verification_key))
      else
        verification_key
      end
    end

    def tap_tweak(point)
      x_only = ECDSA::Format::IntegerOctetString.encode(point.x, 32)
      FROST::Hash.tagged_hash('TapTweak', x_only)
    end

    private_class_method :tap_tweak
  end
end