require 'spec_helper'

RSpec.describe FROST::Refresh do

  let(:ctx) { FROST::Context.new(ECDSA::Group::Secp256k1, FROST::Type::RFC9591) }

  describe "refresh share with dealer" do
    it do
      # Old key generation
      max_signers = 5
      min_signers = 3
      dealer = FROST::Dealer.new(ctx, max_signers, min_signers)
      old_shares = dealer.gen_shares
      group_pubkey = dealer.group_public_key

      # New key generation
      # Signer 2 will be removed and Signers 1, 3, 4 & 5 will remain
      remaining_ids = [1, 3, 4, 5]
      new_max_signers = 4

      # Trusted Dealer new polynomial using zero key.
      new_dealer = FROST::Dealer.new(ctx, new_max_signers, min_signers, zero_key: true)
      refreshing_shares = new_dealer.gen_shares(remaining_ids)

      # Each signer computes a refreshing share.
      refreshed_share = refreshing_shares.map do |share|
        target_share = old_shares.find{|s| s.identifier == share.identifier}
        described_class.refresh_share(target_share, share)
      end

      # Generate signature using refreshed shares.
      msg = ["74657374"].pack("H*")

      share1, share3, _, share5 = refreshed_share
      hiding_nonce1, binding_nonce1 = share1.generate_nonces
      hiding_nonce3, binding_nonce3 = share3.generate_nonces
      hiding_nonce5, binding_nonce5 = share5.generate_nonces
      comm1 = FROST::Commitments.new(1, hiding_nonce1.to_point, binding_nonce1.to_point)
      comm3 = FROST::Commitments.new(3, hiding_nonce3.to_point, binding_nonce3.to_point)
      comm5 = FROST::Commitments.new(5, hiding_nonce5.to_point, binding_nonce5.to_point)
      commitment_list = [comm1, comm3, comm5]
      sig_share1 = FROST.sign(ctx, share1, group_pubkey, [hiding_nonce1, binding_nonce1], msg, commitment_list)
      sig_share3 = FROST.sign(ctx, share3, group_pubkey, [hiding_nonce3, binding_nonce3], msg, commitment_list)
      sig_share5 = FROST.sign(ctx, share5, group_pubkey, [hiding_nonce5, binding_nonce5], msg, commitment_list)
      expect(FROST.verify_share(ctx, 1, share1.to_point, sig_share1, commitment_list, group_pubkey, msg)).to be true
      expect(FROST.verify_share(ctx, 3, share3.to_point, sig_share3, commitment_list, group_pubkey, msg)).to be true
      expect(FROST.verify_share(ctx, 5, share5.to_point, sig_share5, commitment_list, group_pubkey, msg)).to be true
      # Aggregation
      sig = FROST.aggregate(ctx, commitment_list, msg, group_pubkey, [sig_share1, sig_share3, sig_share5])
      expect(FROST.verify(sig, group_pubkey, msg)).to be true
    end
  end
end