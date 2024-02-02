# frozen_string_literal: true
require 'spec_helper'

RSpec.describe FROST do

  shared_examples "Test Vector" do
    it do
      # key generation
      secret = vectors['inputs']['group_secret_key']
      verifying_key = vectors['inputs']['verifying_key_key']
      participants = vectors['inputs']['participant_shares'].map do |p|
        id = p['identifier']
        key_share = p['participant_share']
      end
    end
  end
  describe "Test Vector" do
    context "secp256k1" do
      let(:vectors) { load_fixture("secp256k1/vectors.json") }
      it_behaves_like "Test Vector"
    end
  end
end
