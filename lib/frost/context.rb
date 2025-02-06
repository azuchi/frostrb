module FROST
  class Context

    CTX_STRING_SECP256K1 = "FROST-secp256k1-SHA256-v1"
    CTX_STRING_SECP256K1_TR = "FROST-secp256k1-SHA256-TR-v1"
    CTX_STRING_P256 = "FROST-P256-SHA256-v1"

    attr_reader :group
    attr_reader :type

    # Constructor
    # @param [ECDSA::Group] group The elliptic curve group.
    # @param [Symbol] type FROST::Type
    # @raise [ArgumentError]
    def initialize(group, type)
      raise ArgumentError, "group must be ECDSA::Group." unless group.is_a?(ECDSA::Group)
      FROST::Type.validate!(type)
      @group = group
      @type = type
    end

    # Check this context is taproot or not?
    # @return [Boolean]
    def taproot?
      type == FROST::Type::TAPROOT
    end

    # Get context string.
    # @return [String] context string.
    # @raise [ArgumentError]
    def ctx_string
      case group
      when ECDSA::Group::Secp256k1
        type == FROST::Type::RFC9591 ? CTX_STRING_SECP256K1 : CTX_STRING_SECP256K1_TR
      when ECDSA::Group::Secp256r1
        CTX_STRING_P256
      else
        # TODO support other suite.
        raise RuntimeError, "group #{group} dose not supported."
      end
    end

    # Normalize elliptic curve point.
    # If type is BIP-340, return as x-only public key.
    # @param [ECDSA::Point] point
    # @return [String] Normalized point string with binary format.
    def normalize(point)
      if taproot?
        ECDSA::Format::FieldElementOctetString.encode(point.x, group.field)
      else
        [point.to_hex].pack("H*")
      end
    end

    # Negate nonces depending on context.
    # @param [ECDSA::Point] group_commitment
    # @param [Array] nonces Pair of nonce values (hiding_nonce, binding_nonce) for signer_i.
    # @return [Array] Converted nonces.
    def convert_signer_nocnes(group_commitment, nonces)
      return nonces unless taproot?
      group_commitment.y.even? ? nonces : nonces.map(&:to_negate)
    end

    # Convert commitment share depending on context.
    # @param [ECDSA::Point] group_commitment
    # @param [ECDSA::Point] commitment_share
    # @return [ECDSA::Point] Converted commitment share.
    def convert_commitment_share(group_commitment, commitment_share)
      return commitment_share unless taproot?
      group_commitment.y.even? ? commitment_share : commitment_share.negate
    end

    # Preprocess verify inputs, negating the VerifyingKey and `signature.R` if required by BIP-340.
    # @param [ECDSA::Point] public_key
    # @param [FROST::Signature] signature
    # @return [Array] An array of public_key and signature.
    def pre_verify(public_key, signature)
      if taproot?
        public_key = public_key.y.even? ? public_key : public_key.negate
        r = signature.r.y.even? ? signature.r : signature.r.negate
        [public_key, FROST::Signature.new(self, r, signature.s)]
      else
        [public_key, signature]
      end
    end
  end
end