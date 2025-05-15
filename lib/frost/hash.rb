module FROST
  # Cryptographic hash function using FROST.
  # https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-cryptographic-hash-function
  module Hash

    module_function

    # H1 hash function.
    # @param [String] msg The message to be hashed.
    # @param [FROST::Context] context FROST context.
    # @return [Integer]
    def h1(msg, context)
      hash_to_field(msg, context, "rho")
    end

    # H2 hash function.
    # @param [String] msg The message to be hashed.
    # @param [FROST::Context] context FROST context.
    # @return [Integer]
    def h2(msg, context)
      if context.taproot?
        tagged_hash('BIP0340/challenge', msg)
      else
        hash_to_field(msg, context, "chal")
      end
    end

    # H3 hash function.
    # @param [String] msg The message to be hashed.
    # @param [FROST::Context] context FROST context.
    # @return [Integer]
    def h3(msg, context)
      hash_to_field(msg, context, "nonce")
    end

    # H4 hash function.
    # @param [String] msg The message to be hashed.
    # @param [FROST::Context] context FROST context.
    # @return [String] The hash value.
    def h4(msg, context)
      hash(msg, context, "msg")
    end

    # H5 hash function.
    # @param [String] msg The message to be hashed.
    # @param [FROST::Context] context FROST context.
    # @return [String] The hash value.
    def h5(msg, context)
      hash(msg, context, "com")
    end

    # Hash function for a FROST ciphersuite, used for the DKG.
    # @param [String] msg The message to be hashed.
    # @param [FROST::Context] context FROST context.
    # @return [Integer] The hash value.
    def hdkg(msg, context)
      hash_to_field(msg, context, "dkg")
    end

    def hash_to_field(msg, context, tag)
      raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
      h2c = case context.group
            when ECDSA::Group::Secp256k1
              H2C.get(H2C::Suite::SECP256K1_XMDSHA256_SSWU_NU_, context.ctx_string + tag)
            when ECDSA::Group::Secp256r1
              H2C.get(H2C::Suite::P256_XMDSHA256_SSWU_NU_, context.ctx_string + tag)
            end
      h2c.hash_to_field(msg, 1, context.group.order).first
    end

    def hash(msg, context, tag)
      raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
      Digest::SHA256.digest(context.ctx_string + tag + msg)
    end

    def tagged_hash(tag, msg)
      tag_hash = Digest::SHA256.digest(tag)
      Digest::SHA256.hexdigest(tag_hash + tag_hash + msg).to_i(16)
    end
  end
end