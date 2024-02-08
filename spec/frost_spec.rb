# frozen_string_literal: true
require 'spec_helper'

RSpec.describe FROST do

  shared_examples "Test Vector" do
    it do
      # key generation
      secret_key = FROST::SigningKey.new(vectors['inputs']['group_secret_key'].hex, group)
      coefficients = vectors['inputs']['share_polynomial_coefficients'].map(&:hex)
      polynomial = FROST::Polynomial.new(coefficients.prepend(secret_key.scalar), group)
      share_map = vectors['inputs']['participant_shares'].map do |p|
        id = p['identifier']
        # Calculate participant share.
        share = polynomial.gen_share(id)
        expect(share.share).to eq(p['participant_share'].hex)
        [id, share]
      end.to_h

      round_one_outputs = vectors['round_one_outputs']
      round_one_outputs['outputs'].each do |o|
        hiding_randomness = [o['hiding_nonce_randomness']].pack("H*")
        hiding_nonce = FROST::Nonce.send(:gen_from_random_bytes,
                                         share_map[o['identifier']].to_key, hiding_randomness)
        expect(hiding_nonce.to_hex).to eq(o['hiding_nonce'])
        expect(hiding_nonce.to_point.to_hex).to eq(o['hiding_nonce_commitment'])

        binding_randomness = [o['binding_nonce_randomness']].pack('H*')
        binding_nonce = FROST::Nonce.send(:gen_from_random_bytes,
                                          share_map[o['identifier']].to_key, binding_randomness)
        expect(binding_nonce.to_hex).to eq(o['binding_nonce'])
        expect(binding_nonce.to_point.to_hex).to eq(o['binding_nonce_commitment'])
      end
    end
  end

  describe "Test Vector" do
    context "secp256k1" do
      let(:group) { ECDSA::Group::Secp256k1 }
      let(:vectors) { load_fixture("secp256k1/vectors.json") }
      it_behaves_like "Test Vector", "secp256k1"
    end
  end

end
