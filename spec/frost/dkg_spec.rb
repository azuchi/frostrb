require 'spec_helper'

RSpec.describe FROST::DKG do

  let(:group) { ECDSA::Group::Secp256k1 }
  let(:ctx) { FROST::Context.new(group, FROST::Type::RFC9591) }

  shared_examples "DKG Test Vector" do
    it do
      min_signers = vectors['config']['MIN_PARTICIPANTS']
      max_signers = vectors['config']['MAX_PARTICIPANTS']
      participant1 = vectors['inputs']['1']
      participant2 = vectors['inputs']['2']
      participant3 = vectors['inputs']['3']
      participants = [participant1, participant2, participant3]

      # Round1
      # generate secret and commitments and proof of knowledge.
      received_packages = {}
      secret_packages = {}
      participants.each do |p|
        identifier = p['identifier']
        coeffs = [p['signing_key'].hex, p['coefficient'].hex]
        polynomial = FROST::Polynomial.new(ctx, coeffs)
        secret_packages[identifier] = FROST::DKG::SecretPackage.new(identifier, min_signers, max_signers, polynomial)
        commitments = polynomial.gen_commitments
        p['vss_commitments'].each.with_index do |commitment, i|
          expect(commitments[i].to_hex).to eq(commitment)
        end
        proof = FROST::Signature.decode(ctx, p['proof_of_knowledge'])
        package = FROST::DKG::Package.new(identifier, commitments, proof)
        [1, 2, 3].select{|v| v != identifier }.each do |target|
          received_packages[target] ||= []
          received_packages[target] << package
        end
      end

      # Each participant verify knowledge of proof in received package.
      participants.each do |p|
        identifier = p['identifier']
        secret_package = secret_packages[identifier]
        received_packages[identifier].each do |package|
          expect(described_class.verify_proof_of_knowledge(secret_package, package)).to be true
        end
      end

      # Round 2:
      # Each participant generate share for other participants.
      received_shares = {}
      participants.each do |participant|
        identifier = participant['identifier']
        secret_package = secret_packages[identifier]
        1.upto(max_signers).each do |target|
          next if identifier == target
          received_shares[target] ||= []
          received_shares[target] << [identifier, secret_package.gen_share(target)]
        end
      end

      participants.each do |participant|
        identifier = participant['identifier']
        participant['signing_shares'].each do |from, share|
          received_share = received_shares[identifier].find{|send_by, _| send_by == from.to_i}[1]
          expect(received_share.share).to eq(share.hex)
        end
      end

      # Each participant verify received shares.
      participants.each do |participant|
        identifier = participant['identifier']
        1.upto(max_signers).each do |target|
          next if identifier == target
          received_share = received_shares[identifier].find{|send_by, _| send_by == target}[1]
          received_package = received_packages[identifier].find{|package| package.identifier == target}
          expect(received_package.verify_share(received_share)).to be true
        end
      end

      # Each participant compute signing share.
      secret_shares = {}
      participants.each do |participant|
        identifier = participant['identifier']
        share = described_class.compute_signing_share(secret_packages[identifier], received_shares[identifier].map{|_, share| share})
        secret_shares[identifier] = share
        expect(share.share).to eq(participant['signing_share'].hex)
        expect(share.to_point.to_hex).to eq(participant['verifying_share'])
      end

      # 1 computes group public key.
      group_pubkey = described_class.compute_group_pubkey(secret_packages[1], received_packages[1])
      expect(group_pubkey.to_hex).to eq(vectors['inputs']['verifying_key'])
    end
  end

  describe "Test DKG" do
    context "secp256k1" do
      let(:vectors) { load_fixture("secp256k1/vectors_dkg.json") }
      it_behaves_like "DKG Test Vector", "secp256k1"
    end

    context "P256" do
      let(:group) { ECDSA::Group::Secp256r1 }
      let(:vectors) { load_fixture("p256/vectors_dkg.json") }
      it_behaves_like "DKG Test Vector", "P256"
    end
  end

  shared_examples "sign with dkg" do
    it do
      max_signer = 5
      min_signer = 3

      secret_packages = {}
      round1_outputs = {}
      # Round 1:
      # For each participant, perform the first part of the DKG protocol.
      1.upto(max_signer) do |i|
        secret_package = FROST::DKG.generate_secret(ctx, i, min_signer, max_signer)
        secret_packages[i] = secret_package
        round1_outputs[i] = secret_package.public_package
      end

      # Each participant send their commitments and proof to other participants.
      received_package = {}
      1.upto(max_signer) do |i|
        received_package[i] = round1_outputs.select {|k, _| k != i}.values
      end

      # Each participant verify knowledge of proof in received package.
      received_package.each do |id, packages|
        secret_package = secret_packages[id]
        packages.each do |package|
          expect(FROST::DKG.verify_proof_of_knowledge(secret_package, package)).to be true
        end
      end

      # Round 2:
      # Each participant generate share for other participants and send it.
      received_shares = {}
      1.upto(max_signer) do |i|
        secret_package = secret_packages[i] # own secret
        1.upto(max_signer) do |o|
          next if i == o
          received_shares[o] ||= []
          received_shares[o] << [i, secret_package.gen_share(o)]
        end
      end

      # Each participant verify received shares.
      1.upto(max_signer) do |i|
        received_shares[i].each do |send_by, share|
          target_package = received_package[i].find{ |package| package.identifier == send_by }
          expect(target_package.verify_share(share)).to be true
        end
      end

      # Each participant compute signing share.
      signing_shares = {}
      1.upto(max_signer) do |i|
        shares = received_shares[i].map{|_, share| share}
        signing_shares[i] = FROST::DKG.compute_signing_share(secret_packages[i], shares)
      end

      # Compute group public key.
      compute_pubkeys = 1.upto(max_signer).map do |i|
        FROST::DKG.compute_group_pubkey(secret_packages[i], received_package[i])
      end
      # All participants calculate the same group pubkey.
      expect(compute_pubkeys.uniq.length).to eq(1)
      group_pubkey = compute_pubkeys.first

      # FROST signing process with dkg
      # group_pubkey = compute_pubkeys.first
      msg = ["74657374"].pack("H*")

      # Round 1: Generate nonce and commitment
      share1 = signing_shares[1]
      share2 = signing_shares[2]
      share4 = signing_shares[4]
      hiding_nonce1 = FROST::Nonce.gen_from_secret(share1)
      binding_nonce1 = FROST::Nonce.gen_from_secret(share1)
      hiding_nonce2 = FROST::Nonce.gen_from_secret(share2)
      binding_nonce2 = FROST::Nonce.gen_from_secret(share2)
      hiding_nonce4 = FROST::Nonce.gen_from_secret(share4)
      binding_nonce4 = FROST::Nonce.gen_from_secret(share4)

      comm1 = FROST::Commitments.new(share1.identifier, hiding_nonce1.to_point, binding_nonce1.to_point)
      comm2 = FROST::Commitments.new(share2.identifier, hiding_nonce2.to_point, binding_nonce2.to_point)
      comm4 = FROST::Commitments.new(share4.identifier, hiding_nonce4.to_point, binding_nonce4.to_point)
      commitment_list = [comm1, comm2, comm4]

      # Round 2: each participant generates their signature share(1 and 2, 4)
      sig_share1 = FROST.sign(ctx, share1, group_pubkey, [hiding_nonce1, binding_nonce1], msg, commitment_list)
      sig_share2 = FROST.sign(ctx, share2, group_pubkey, [hiding_nonce2, binding_nonce2], msg, commitment_list)
      sig_share4 = FROST.sign(ctx, share4, group_pubkey, [hiding_nonce4, binding_nonce4], msg, commitment_list)

      expect(FROST.verify_share(ctx, 1, share1.to_point, sig_share1, commitment_list, group_pubkey, msg)).to be true
      expect(FROST.verify_share(ctx, 2, share2.to_point, sig_share2, commitment_list, group_pubkey, msg)).to be true
      expect(FROST.verify_share(ctx, 4, share4.to_point, sig_share4, commitment_list, group_pubkey, msg)).to be true

      # Aggregation
      sig = FROST.aggregate(ctx, commitment_list, msg, group_pubkey, [sig_share1, sig_share2, sig_share4])

      expect(FROST.verify(sig, group_pubkey, msg)).to be true
    end
  end

  describe "Test sign with DKG" do
    context "secp256k1" do
      it_behaves_like "sign with dkg", "secp256k1"
    end

    context "P256" do
      let(:group) { ECDSA::Group::Secp256r1 }
      it_behaves_like "sign with dkg", "P256"
    end
  end

end
