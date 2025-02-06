# frozen_string_literal: true

require_relative "frost/version"
require 'ecdsa_ext'
require 'securerandom'
require 'digest'
require 'h2c'

module FROST
  class Error < StandardError; end

  autoload :Context, 'frost/context'
  autoload :Signature, "frost/signature"
  autoload :Commitments, "frost/commitments"
  autoload :Hash, "frost/hash"
  autoload :Nonce, "frost/nonce"
  autoload :SecretShare, "frost/secret_share"
  autoload :Polynomial, "frost/polynomial"
  autoload :SigningKey, "frost/signing_key"
  autoload :DKG, "frost/dkg"
  autoload :Repairable, "frost/repairable"

  module Type
    RFC9591 = :rfc9591
    TAPROOT = :taproot

    module_function

    # Check whether valid type or not.
    # @param [Symbol] type
    # @return [Boolean]
    def supported?(type)
      [RFC9591, TAPROOT].include?(type)
    end

    # Validate type
    # @param [Symbol] type
    # @raise [ArgumentError]
    def validate!(type)
      raise ArgumentError, "Unsupported type: #{type}." unless supported?(type)
    end
  end

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
  # @param [FROST::Context] context
  # @param [ECDSA::Point] group_pubkey
  # @param [Array] commitment_list The list of commitments issued by each participants.
  # This list must be sorted in ascending order by identifier.
  # @param [String] msg The message to be signed.
  # @return [Hash] The hash of binding factor.
  def compute_binding_factors(context, group_pubkey, commitment_list, msg)
    raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)
    raise ArgumentError, "group_pubkey and context groups are different." unless context.group == group_pubkey.group

    msg_hash = Hash.h4(msg, context)
    encoded_commitment = Commitments.encode_group_commitment(commitment_list)
    encoded_commitment_hash = Hash.h5(encoded_commitment, context)
    rho_input_prefix = [group_pubkey.to_hex].pack("H*") + msg_hash + encoded_commitment_hash
    binding_factors = {}
    commitment_list.each do |commitments|
      preimage = rho_input_prefix + encode_identifier(commitments.identifier, context.group)
      binding_factors[commitments.identifier] = Hash.h1(preimage, context)
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
  # If context type is BIP-340(taproot), only the X coordinate of R and group_pubkey are hashed, unlike vanilla FROST.
  # @param [ECDSA::Point] group_commitment The group commitment.
  # @param [ECDSA::Point] group_pubkey The public key corresponding to the group signing key.
  # @param [String] msg The message to be signed.
  # @return [Integer] challenge
  def compute_challenge(context, group_commitment, group_pubkey, msg)
    raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
    raise ArgumentError, "group_commitment must be ECDSA::Point." unless group_commitment.is_a?(ECDSA::Point)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)
    raise ArgumentError, "group_pubkey and context groups are different." unless context.group == group_pubkey.group

    preimage = context.normalize(group_commitment) + context.normalize(group_pubkey) + msg
    Hash.h2(preimage, context)
  end

  # Generate signature share.
  # @param [FROST::Context] context FROST context.
  # @param [FROST::SecretShare] secret_share Signer secret key share.
  # @param [ECDSA::Point] group_pubkey Public key corresponding to the group signing key.
  # @param [Array] nonces Pair of nonce values (hiding_nonce, binding_nonce) for signer_i.
  # @param [String] msg The message to be signed
  # @param [Array] commitment_list A list of commitments issued by each participant.
  # @return [Integer] A signature share.
  def sign(context, secret_share, group_pubkey, nonces, msg, commitment_list)
    raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)
    raise ArgumentError, "group_pubkey and context groups are different." unless context.group == group_pubkey.group

    identifier = secret_share.identifier
    # Compute binding factors
    binding_factors = compute_binding_factors(context, group_pubkey, commitment_list, msg)
    binding_factor = binding_factors[identifier]

    # Compute group commitment
    group_commitment = compute_group_commitment(commitment_list, binding_factors)

    # Compute Lagrange coefficient
    identifiers = commitment_list.map(&:identifier)
    lambda_i = Polynomial.derive_interpolating_value(identifiers, identifier, context.group)

    # Compute the per-message challenge
    challenge = compute_challenge(context, group_commitment, group_pubkey, msg)

    # Compute the signature share
    hiding_nonce, binding_nonce = context.convert_signer_nocnes(group_commitment, nonces)
    field = ECDSA::PrimeField.new(group_pubkey.group.order)
    field.mod(hiding_nonce.value +
                field.mod(binding_nonce.value * binding_factor) + field.mod(lambda_i * secret_share.share * challenge))
  end

  # Aggregates the signature shares to produce a final signature that can be verified with the group public key.
  # @param [FROST::Context] context FROST context.
  # @param [Array] commitment_list A list of commitments issued by each participant.
  # @param [String] msg The message to be signed.
  # @param [ECDSA::Point] group_pubkey Public key corresponding to the group signing key.
  # @param [Array] sig_shares A set of signature shares z_i, integer values.
  # @return [FROST::Signature] Schnorr signature.
  def aggregate(context, commitment_list, msg, group_pubkey, sig_shares)
    raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)
    raise ArgumentError, "group_pubkey and context groups are different." unless context.group == group_pubkey.group
    raise ArgumentError, "The numbers of commitment_list and sig_shares do not match." unless commitment_list.length == sig_shares.length

    binding_factors = compute_binding_factors(context, group_pubkey, commitment_list, msg)
    group_commitment = compute_group_commitment(commitment_list, binding_factors)

    field = ECDSA::PrimeField.new(context.group.order)
    s = sig_shares.inject(0) do |sum, z_i|
      raise ArgumentError, "sig_shares must be array of integer" unless z_i.is_a?(Integer)
      field.mod(sum + z_i)
    end

    Signature.new(context, group_commitment, field.mod(s))
  end

  # Verify signature share.
  # @param [FROST::Context] context FROST context.
  # @param [Integer] identifier Identifier i of the participant.
  # @param [ECDSA::Point] pubkey_i The public key for the i-th participant
  # @param [Integer] sig_share_i Integer value indicating the signature share as produced
  # in round two from the i-th participant.
  # @param [Array] commitment_list A list of commitments issued by each participant.
  # @param [ECDSA::Point] group_pubkey Public key corresponding to the group signing key.
  # @param [String] msg The message to be signed.
  # @return [Boolean] Verification result.
  def verify_share(context, identifier, pubkey_i, sig_share_i, commitment_list, group_pubkey, msg)
    raise ArgumentError "context must be FROST::Context." unless context.is_a?(FROST::Context)
    raise ArgumentError, "identifier must be Integer." unless identifier.is_a?(Integer)
    raise ArgumentError, "sig_share_i must be Integer." unless sig_share_i.is_a?(Integer)
    raise ArgumentError, "pubkey_i must be ECDSA::Point." unless pubkey_i.is_a?(ECDSA::Point)
    raise ArgumentError, "group_pubkey must be ECDSA::Point." unless group_pubkey.is_a?(ECDSA::Point)
    raise ArgumentError, "group_pubkey and context groups are different." unless context.group == group_pubkey.group

    binding_factors = compute_binding_factors(context, group_pubkey, commitment_list, msg)
    binding_factor = binding_factors[identifier]
    group_commitment = compute_group_commitment(commitment_list, binding_factors)
    comm_i = commitment_list.find{|c| c.identifier == identifier}
    hiding_commitment = comm_i.hiding
    binding_commitment = comm_i.binding
    raise ArgumentError, "hiding_commitment must be ECDSA::Point." unless hiding_commitment.is_a?(ECDSA::Point)
    raise ArgumentError, "binding_commitment must be ECDSA::Point." unless binding_commitment.is_a?(ECDSA::Point)

    comm_share = context.convert_commitment_share(group_commitment, hiding_commitment + binding_commitment * binding_factor)
    challenge = compute_challenge(context, group_commitment, group_pubkey, msg)
    identifiers = commitment_list.map(&:identifier)
    lambda_i = Polynomial.derive_interpolating_value(identifiers, identifier, context.group)
    l = context.group.generator * sig_share_i
    r = comm_share + pubkey_i * (challenge * lambda_i)
    l == r
  end

  # Verify signature.
  # @param [FROST::Signature] signature
  # @param [ECDSA::Point] public_key
  # @param [String] msg
  # @return [Boolean] Verification result.
  def verify(signature, public_key, msg)
    raise ArgumentError, "signature must be FROST::Signature" unless signature.is_a?(FROST::Signature)
    raise ArgumentError, "public_key must be ECDSA::Point" unless public_key.is_a?(ECDSA::Point)
    raise ArgumentError, "public_key and context groups are different." unless signature.context.group == public_key.group
    raise ArgumentError, "msg must be String." unless msg.is_a?(String)

    context = signature.context
    public_key, signature = context.pre_verify(public_key, signature)

    # Compute challenge
    challenge = compute_challenge(context, signature.r, public_key, msg)

    s_g = public_key.group.generator * signature.s
    c_p = public_key * challenge
    result = (s_g + signature.r.negate + c_p.negate) * public_key.group.cofactor
    result.infinity?
  end
end
