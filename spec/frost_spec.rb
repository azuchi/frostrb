# frozen_string_literal: true
require 'spec_helper'

RSpec.describe FROST do

  shared_examples "Test Vector" do
    it do
      # key generation
      secret_key = FROST::SigningKey.new(vectors['inputs']['group_secret_key'].hex, group)
      coefficients = vectors['inputs']['share_polynomial_coefficients'].map(&:hex)
      polynomial = FROST::Polynomial.new(coefficients << secret_key.scalar, group)
      verifying_key = vectors['inputs']['verifying_key_key']
      participants = vectors['inputs']['participant_shares'].map do |p|
        id = p['identifier']
        expect(polynomial.gen_share(id).share).to eq(p['participant_share'].hex)
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
