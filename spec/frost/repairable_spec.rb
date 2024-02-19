require 'spec_helper'

RSpec.describe FROST::Repairable do

  let(:group) { ECDSA::Group::Secp256k1 }
  let(:max_signers) { 5 }
  let(:min_signers) { 3 }
  let(:dealer) { FROST::SigningKey.generate(group) }

  shared_examples "Reparable Test" do
    it do
      # Dealer generate shares.
      polynomial = dealer.gen_poly(min_signers - 1)
      shares = 1.upto(max_signers).map {|identifier| polynomial.gen_share(identifier) }

      # Signer 2 will lose their share
      # Signers (helpers) 1, 4 and 5 will help signer 2 (participant) to recover their share
      helper1 = shares[0]
      helper4 = shares[3]
      helper5 = shares[4]
      helper_shares = [helper1, helper4, helper5]
      helpers = helper_shares.map(&:identifier)
      participant_share = shares[1]

      # Each helper computes delta values.
      received_values = {}
      helper_shares.each do |helper_share|
        delta_values = FROST::Repairable.step1(helpers, participant_share.identifier, helper_share)
        delta_values.each do |target_id, value|
          received_values[target_id] ||= []
          received_values[target_id] << value
        end
      end

      # Each helper send sum value to participant.
      participant_received_values = []
      received_values.each do |_, values|
        participant_received_values << FROST::Repairable.step2(values, group)
      end

      repair_share = FROST::Repairable.step3(2, participant_received_values, group)
      expect(repair_share.share).to eq(participant_share.share)
    end
  end

  describe "repair" do
    context "secp256k1" do
      let(:vector) { load_fixture("secp256k1/repair-share.json") }
    end
    it_behaves_like "Reparable Test", "secp256k1"
  end

  describe "step1" do
    it do
      # Dealer generate shares.
      polynomial = dealer.gen_poly(min_signers - 1)
      shares = 1.upto(max_signers).map {|identifier| polynomial.gen_share(identifier) }
      helper1 = shares[0]
      helper4 = shares[3]
      helper5 = shares[4]
      helper_shares = [helper1, helper4, helper5]
      helpers = helper_shares.map(&:identifier)
      participant = shares[1]

      # Generate deltas for helper 4
      deltas = described_class.step1(helpers, participant.identifier, helper4)

      lagrange_coefficient = FROST::Polynomial.derive_interpolating_value(helpers, helper4.identifier, group, x: participant.identifier)

      field = ECDSA::PrimeField.new(group.order)
      rhs = field.mod(deltas.values.sum)
      lhs = field.mod(helper4.share * lagrange_coefficient)
      expect(rhs).to eq(lhs)
    end
  end

  shared_examples "repair share step2" do
    it do
      values = vectors['scalar_generation']
      value1 = values['random_scalar_1']
      value2 = values['random_scalar_2']
      value3 = values['random_scalar_3']
      expected = described_class.step2([value1, value2, value3].map(&:hex), group)
      expect(expected).to eq(values['random_scalar_sum'].hex)
    end
  end

  describe "#step2" do
    context "secp256k1" do
      let(:vectors) { load_fixture("secp256k1/repair-share.json") }
      it_behaves_like "repair share step2", "secp256k1"
    end
    context "P256" do
      let(:group) { ECDSA::Group::Secp256r1 }
      let(:vectors) { load_fixture("p256/repair-share.json") }
      it_behaves_like "repair share step2", "P256"
    end
  end

  shared_examples "repair share step3" do
    it do
      sigmas = vectors['sigma_generation']
      sigma1 = sigmas['sigma_1']
      sigma2 = sigmas['sigma_2']
      sigma3 = sigmas['sigma_3']
      sigma4 = sigmas['sigma_4']

      expected = described_class.step3(2, [sigma1, sigma2, sigma3, sigma4].map(&:hex), group)
      expect(expected.share).to eq(sigmas['sigma_sum'].hex)
      expect(expected.identifier).to eq(2)
    end
  end

  describe "#step2" do
    context "secp256k1" do
      let(:vectors) { load_fixture("secp256k1/repair-share.json") }
      it_behaves_like "repair share step3", "secp256k1"
    end
    context "P256" do
      let(:group) { ECDSA::Group::Secp256r1 }
      let(:vectors) { load_fixture("p256/repair-share.json") }
      it_behaves_like "repair share step3", "P256"
    end
  end
end