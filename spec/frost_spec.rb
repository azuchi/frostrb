# frozen_string_literal: true
require 'spec_helper'

RSpec.describe FROST do

  shared_examples "Test Vector" do
    it do
      # key generation
      secret_key = FROST::SigningKey.new(vectors['inputs']['group_secret_key'].hex, group)
      group_pubkey = [vectors['inputs']['group_public_key']].pack("H*")
      group_pubkey = ECDSA::Format::PointOctetString.decode(group_pubkey, group)
      msg = [vectors['inputs']['message']].pack("H*")
      coefficients = vectors['inputs']['share_polynomial_coefficients'].map(&:hex)
      polynomial = FROST::Polynomial.new(coefficients.prepend(secret_key.scalar), group)
      share_map = vectors['inputs']['participant_shares'].map do |p|
        id = p['identifier']
        # Calculate participant share.
        share = polynomial.gen_share(id)
        expect(share.share).to eq(p['participant_share'].hex)
        [id, share]
      end.to_h

      # Round 1: Generate nonce and commitment
      round_one_outputs = vectors['round_one_outputs']
      nonce_map = {}
      commitment_list = round_one_outputs['outputs'].map do |o|
        identifier = o['identifier']
        hiding_randomness = [o['hiding_nonce_randomness']].pack("H*")
        hiding_nonce = FROST::Nonce.send(:gen_from_random_bytes,
                                         share_map[identifier], hiding_randomness)
        expect(hiding_nonce.to_hex).to eq(o['hiding_nonce'])
        hiding_commitment = hiding_nonce.to_point
        expect(hiding_commitment.to_hex).to eq(o['hiding_nonce_commitment'])

        binding_randomness = [o['binding_nonce_randomness']].pack('H*')
        binding_nonce = FROST::Nonce.send(:gen_from_random_bytes,
                                          share_map[identifier], binding_randomness)
        expect(binding_nonce.to_hex).to eq(o['binding_nonce'])
        binding_commitment = binding_nonce.to_point
        expect(binding_commitment.to_hex).to eq(o['binding_nonce_commitment'])
        nonce_map[identifier] = [hiding_nonce, binding_nonce]
        FROST::Commitments.new(o['identifier'], hiding_commitment, binding_commitment)
      end

      # Round 2: each participant generates their signature share
      round_two_outputs = vectors['round_two_outputs']

      binding_factors = FROST.compute_binding_factors(group_pubkey, commitment_list, msg)
      round_one_outputs['outputs'].each do |o|
        expect(binding_factors[o['identifier']]).to eq(o['binding_factor'].hex)
      end

      sig_shares = round_two_outputs['outputs'].map do |o|
        identifier = o['identifier']
        signing_share = share_map[identifier]
        sig_share = FROST.sign(signing_share, group_pubkey, nonce_map[identifier], msg, commitment_list)
        expect(sig_share).to eq(o['sig_share'].hex)
        expect(FROST.verify_share(
          identifier,
          signing_share.to_point,
          sig_share,
          commitment_list, group_pubkey, msg)).to be true
        sig_share
      end

      # Aggregation
      sig = FROST.aggregate(commitment_list, msg, group_pubkey, sig_shares)
      expect(sig.to_hex).to eq(vectors['final_output']['sig'])

      expect(FROST.verify(sig, group_pubkey, msg)).to be true
    end
  end

  shared_examples "frost process" do
    it do
      # Dealer generate secret.
      secret = FROST::SigningKey.generate(group)
      group_pubkey = secret.to_point
      # Generate polynomial
      polynomial = secret.gen_poly(1)
      # Calculate secret shares.
      share1 = polynomial.gen_share(1)
      share2 = polynomial.gen_share(2)
      share3 = polynomial.gen_share(3)

      # Round 1: Generate nonce and commitment
      ## each party generate hiding and binding nonce.
      hiding_nonce1 = FROST::Nonce.gen_from_secret(share1)
      binding_nonce1 = FROST::Nonce.gen_from_secret(share1)
      hiding_nonce3 = FROST::Nonce.gen_from_secret(share3)
      binding_nonce3 = FROST::Nonce.gen_from_secret(share3)

      comm1 = FROST::Commitments.new(1, hiding_nonce1.to_point, binding_nonce1.to_point)
      comm3 = FROST::Commitments.new(3, hiding_nonce3.to_point, binding_nonce3.to_point)
      commitment_list = [comm1, comm3]

      msg = ["74657374"].pack("H*")

      # Round 2: each participant generates their signature share(1 and 3)
      sig_share1 = FROST.sign(share1, group_pubkey, [hiding_nonce1, binding_nonce1], msg, commitment_list)
      sig_share3 = FROST.sign(share3, group_pubkey, [hiding_nonce3, binding_nonce3], msg, commitment_list)

      expect(FROST.verify_share(1, share1.to_point, sig_share1, commitment_list, group_pubkey, msg)).to be true
      expect(FROST.verify_share(3, share3.to_point, sig_share3, commitment_list, group_pubkey, msg)).to be true

      # Aggregation
      sig = FROST.aggregate(commitment_list, msg, group_pubkey, [sig_share1, sig_share3])

      expect(FROST.verify(sig, group_pubkey, msg)).to be true
    end
  end

  describe "Test Vector" do
    context "secp256k1" do
      let(:group) { ECDSA::Group::Secp256k1 }
      let(:vectors) { load_fixture("secp256k1/vectors.json") }
      it_behaves_like "Test Vector", "secp256k1"
      it_behaves_like "frost process", "secp256k1"
    end

    context "secp256k1 big identifiers" do
      let(:group) { ECDSA::Group::Secp256k1 }
      let(:vectors) { load_fixture("secp256k1/vectors-big-identifier.json") }
      it_behaves_like "Test Vector", "secp256k1 with big identifier"
    end

    context "p256" do
      let(:group) { ECDSA::Group::Secp256r1 }
      let(:vectors) { load_fixture("p256/vectors.json") }
      it_behaves_like "Test Vector", "p256"
      it_behaves_like "frost process", "p256"
    end

    context "p256 big identifiers" do
      let(:group) { ECDSA::Group::Secp256r1 }
      let(:vectors) { load_fixture("p256/vectors-big-identifier.json") }
      it_behaves_like "Test Vector", "p256 with big identifier"
    end
  end

end
