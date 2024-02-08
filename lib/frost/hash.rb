module FROST
  # Cryptographic hash function using FROST.
  # https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-cryptographic-hash-function
  module Hash

    module_function

    CTX_STRING_SECP256K1 = "FROST-secp256k1-SHA256-v1"

    # H1 hash function.
    # @param [String] msg The message to be hashed.
    # param [ECDSA::Group] group The elliptic curve group.
    # @return [Integer]
    def h1(msg, group)
      hash_to_field(msg, group, "rho")
    end

    # H3 hash function.
    # @param [String] msg The message to be hashed.
    # @param [ECDSA::Group] group The elliptic curve group.
    # @return [Integer]
    def h3(msg, group)
      hash_to_field(msg, group, "nonce")
    end

    # H4 hash function.
    # @param [String] msg The message to be hashed.
    # @param [ECDSA::Group] group The elliptic curve group.
    # @return [String] The hash value.
    def h4(msg, group)
      hash(msg, group, "msg")
    end

    # H5 hash function.
    # @param [String] msg The message to be hashed.
    # @param [ECDSA::Group] group The elliptic curve group.
    # @return [String] The hash value.
    def h5(msg, group)
      hash(msg, group, "com")
    end

    def hash_to_field(msg, group, context)
      case group
      when ECDSA::Group::Secp256k1
        dst = CTX_STRING_SECP256K1 + context
        h2c = H2C.get(H2C::Suite::SECP256K1_XMDSHA256_SSWU_NU_, dst)
        h2c.hash_to_field(msg, 1, ECDSA::Group::Secp256k1.order).first
      else
        # TODO support other suite.
        raise RuntimeError, "group #{group} dose not supported."
      end
    end

    def hash(msg, group, context)
      case group
      when ECDSA::Group::Secp256k1
        Digest::SHA256.digest(CTX_STRING_SECP256K1 + context + msg)
      else
        # TODO support other suite.
        raise RuntimeError, "group #{group} dose not supported."
      end
    end
  end
end