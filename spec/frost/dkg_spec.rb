require 'spec_helper'

RSpec.describe FROST::DKG do

  let(:group) { ECDSA::Group::Secp256k1 }

  describe "sign with dkg" do
    it do
      max_signer = 5
      min_signer = 3

      secrets = {}
      round1_outputs = {}
      # Round 1: For each participant, perform the first part of the DKG protocol.
      1.upto(max_signer) do |i|
        polynomial, package = FROST::DKG.part1(i, min_signer, max_signer, group)
        secrets[i] = polynomial
        round1_outputs[i] = package
      end

      # Each participant send their commitments and proof to other participants.
      received_package = {}
      1.upto(max_signer) do |i|
        received_package[i] = round1_outputs.select {|k, _| k != i}.values
      end

      # Each participant verify knowledge of proof in received package.
      received_package.each do |id, packages|
        packages.each do |package|
          expect(FROST::DKG.verify_proof_of_knowledge(package)).to be true
        end
      end
    end
  end

end
