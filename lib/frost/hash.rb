module FROST
  # Cryptographic hash function using FROST.
  # https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-cryptographic-hash-function
  module Hash

    module_function

    CTX_STRING_SECP256K1 = "FROST-secp256k1-SHA256-v1"

    # H3 hash function.
    # @param [String] msg Message to be hashed.
    # @param [ECDSA::Group] group group.
    # @return [Integer]
    def h3(msg, group)
      case group
      when ECDSA::Group::Secp256k1
        dst = CTX_STRING_SECP256K1 + "nonce"
        h2c = H2C.get(H2C::Suite::SECP256K1_XMDSHA256_SSWU_NU_, dst)
        h2c.hash_to_field(msg, 1, ECDSA::Group::Secp256k1.order).first
      else
        # TODO support other suite.
        raise RuntimeError, "group #{group} dose not supported."
      end
    end
  end
end