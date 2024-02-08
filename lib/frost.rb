# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa_ext'
require 'securerandom'
require 'digest'
require 'h2c'

module FROST
  class Error < StandardError; end

  autoload :Commitments, "frost/commitments"
  autoload :Hash, "frost/hash"
  autoload :Nonce, "frost/nonce"
  autoload :SecretShare, "frost/secret_share"
  autoload :Polynomial, "frost/polynomial"
  autoload :SigningKey, "frost/signing_key"

  module_function

  # Encode identifier
  # @param [Integer] identifier
  # @param [ECDSA::Group] group
  # @return [String] The encoded identifier
  def encode_identifier(identifier, group)
    case group
    when ECDSA::Group::Secp256k1
      ECDSA::Format::IntegerOctetString.encode(identifier, 32)
    else
      raise RuntimeError, "group #{group} dose not supported."
    end
  end

  # Compute binding factors.
  # https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-binding-factors-computation
  # @param [ECDSA::Point] group_pubkey
  # @param [Array] commitment_list The list of commitments issued by each participants.
  # This list must be sorted in ascending order by identifier.
  # @param [String] msg The message to be signed.
  # @return [Array] The list of binding factor.
  def compute_binding_factors(group_pubkey, commitment_list, msg)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)

    msg_hash = Hash.h4(msg, group_pubkey.group)
    encoded_commitment = Commitments.encode_group_commitment(commitment_list)
    encoded_commitment_hash = Hash.h5(encoded_commitment, group_pubkey.group)
    rho_input_prefix = [group_pubkey.to_hex].pack("H*") + msg_hash + encoded_commitment_hash
    commitment_list.map do |commitments|
      preimage = rho_input_prefix + encode_identifier(commitments.identifier, group_pubkey.group)
      Hash.h1(preimage, group_pubkey.group)
    end
  end
end
