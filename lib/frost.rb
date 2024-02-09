# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa_ext'
require 'securerandom'
require 'digest'
require 'h2c'

module FROST
  class Error < StandardError; end

  autoload :Signature, "frost/signature"
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
    when ECDSA::Group::Secp256k1, ECDSA::Group::Secp256r1
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
  # @return [Hash] The hash of binding factor.
  def compute_binding_factors(group_pubkey, commitment_list, msg)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)

    msg_hash = Hash.h4(msg, group_pubkey.group)
    encoded_commitment = Commitments.encode_group_commitment(commitment_list)
    encoded_commitment_hash = Hash.h5(encoded_commitment, group_pubkey.group)
    rho_input_prefix = [group_pubkey.to_hex].pack("H*") + msg_hash + encoded_commitment_hash
    binding_factors = {}
    commitment_list.each do |commitments|
      preimage = rho_input_prefix + encode_identifier(commitments.identifier, group_pubkey.group)
      binding_factors[commitments.identifier] = Hash.h1(preimage, group_pubkey.group)
    end
    binding_factors
  end

  # Compute the group commitment
  # @param [Array] commitment_list The list of commitments.
  # @param [Hash] binding_factors The map of binding factors.
  # @return [ECDSA::Point]
  def compute_group_commitment(commitment_list, binding_factors)
    commitment_list.inject(commitment_list.first.hiding.group.infinity) do |sum, commitments|
      binding_factor = binding_factors[commitments.identifier]
      binding_nonce = commitments.binding * binding_factor
      binding_nonce + commitments.hiding + sum
    end
  end

  # Create the per-message challenge.
  # @param [ECDSA::Point] group_commitment The group commitment.
  # @param [ECDSA::Point] group_pubkey The public key corresponding to the group signing key.
  # @param [String] msg The message to be signed.
  def compute_challenge(group_commitment, group_pubkey, msg)
    raise ArgumentError, "group_commitment must be ECDSA::Point." unless group_commitment.is_a?(ECDSA::Point)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)

    input = [group_commitment.to_hex + group_pubkey.to_hex].pack("H*") + msg
    Hash.h2(input, group_commitment.group)
  end

  # Generate signature share.
  # @param [FROST::SecretShare] secret_share Signer secret key share.
  # @param [ECDSA::Point] group_pubkey Public key corresponding to the group signing key.
  # @param [Array] nonces Pair of nonce values (hiding_nonce, binding_nonce) for signer_i.
  # @param [String] msg The message to be signed
  # @param [Array] commitment_list A list of commitments issued by each participant.
  # @return [Integer] A signature share.
  def sign(secret_share, group_pubkey, nonces, msg, commitment_list)
    identifier = secret_share.identifier
    # Compute binding factors
    binding_factors = compute_binding_factors(group_pubkey, commitment_list, msg)
    binding_factor = binding_factors[identifier]

    # Compute group commitment
    group_commitment = compute_group_commitment(commitment_list, binding_factors)

    # Compute Lagrange coefficient
    identifiers = commitment_list.map(&:identifier)
    lambda_i = Polynomial.derive_interpolating_value(identifiers, identifier, group_pubkey.group)

    # Compute the per-message challenge
    challenge = compute_challenge(group_commitment, group_pubkey, msg)

    # Compute the signature share
    hiding_nonce, binding_nonce = nonces
    field = ECDSA::PrimeField.new(group_pubkey.group.order)
    field.mod(hiding_nonce.value +
                field.mod(binding_nonce.value * binding_factor) + field.mod(lambda_i * secret_share.share * challenge))
  end

  # Aggregates the signature shares to produce a final signature that can be verified with the group public key.
  # @param [Array] commitment_list A list of commitments issued by each participant.
  # @param [String] msg The message to be signed.
  # @param [ECDSA::Point] group_pubkey Public key corresponding to the group signing key.
  # @param [Array] sig_shares A set of signature shares z_i, integer values.
  # @return [FROST::Signature] Schnorr signature.
  def aggregate(commitment_list, msg, group_pubkey, sig_shares)
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)

    binding_factors = compute_binding_factors(group_pubkey, commitment_list, msg)
    group_commitment = compute_group_commitment(commitment_list, binding_factors)

    field = group_pubkey.group.field
    s = sig_shares.inject(0) { |sum, s| field.mod(sum + s) }

    Signature.new(group_commitment, s)
  end

  # Verify signature.
  # @param [FROST::Signature] signature
  # @param [ECDSA::Point] public_key
  # @param [String] msg
  # @return [Boolean] Verification result.
  def verify(signature, public_key, msg)
    # Compute challenge
    challenge = compute_challenge(signature.r, public_key, msg)

    s_g = public_key.group.generator * signature.s
    c_p = public_key * challenge
    result = (s_g + signature.r.negate + c_p.negate) * public_key.group.cofactor
    result.infinity?
  end
end
