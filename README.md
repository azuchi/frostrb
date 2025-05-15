# FROST for Ruby [![Build Status](https://github.com/azuchi/frostrb/actions/workflows/main.yml/badge.svg?branch=master)](https://github.com/azuchi/frostrb/actions/workflows/main.yml)

This library is ruby implementations of ['Two-Round Threshold Schnorr Signatures with FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/).

Note: This library has not been security audited and tested widely, so should not be used in production.

The cipher suites currently supported by this library are:

* [secp256k1, SHA-256](https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-frostsecp256k1-sha-256)
* [P-256, SHA-256](https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-frostp-256-sha-256)
* secp256k1, Taproot

Note: The implementation for Taproot is based on [frost-secp256k1-tr](https://github.com/ZcashFoundation/frost/tree/main/frost-secp256k1-tr),
but since it is not an official BIP, it may change in the future.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'frostrb', require: 'frost'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install frostrb

## Usage

```ruby
require 'frost'

# Setup context.
ctx = FROST::Context.new(ECDSA::Group::Secp256k1, FROST::Type::RFC9591)

# Dealer generate secret.
secret = FROST::SigningKey.generate(ctx)
group_pubkey = secret.to_point

# Generate polynomial(f(x) = ax + b)
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
sig_share1 = FROST.sign(ctx, share1, group_pubkey, [hiding_nonce1, binding_nonce1], msg, commitment_list)
sig_share3 = FROST.sign(ctx, share3, group_pubkey, [hiding_nonce3, binding_nonce3], msg, commitment_list)

# verify signature share
FROST.verify_share(1, share1.to_point, sig_share1, commitment_list, group_pubkey, msg)
FROST.verify_share(3, share3.to_point, sig_share3, commitment_list, group_pubkey, msg)

# Aggregation
sig = FROST.aggregate(ctx, commitment_list, msg, group_pubkey, [sig_share1, sig_share3])

# verify final signature
FROST.verify(sig, group_pubkey, msg)
```

### Bitcoin support

When using Bitcoin(taproot), the context type must be `FROST::Type::Taproot` instead of `FROST::Type::RFC9591`.

```ruby
ctx = FROST::Context.new(ECDSA::Group::Secp256k1, FROST::Type::TAPROOT)
```

### Using DKG

DKG can be run as below.

```ruby
# Setup context.
ctx = FROST::Context.new(ECDSA::Group::Secp256k1, FROST::Type::RFC9591)

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

# Each participant computes signing share.
signing_shares = {}
1.upto(max_signer) do |i|
  shares = received_shares[i].map{|_, share| share}
  signing_shares[i] = FROST::DKG.compute_signing_share(secret_packages[i], received_package[i], shares)
end

# Participant 1 compute group public key.
group_pubkey = FROST::DKG.compute_group_pubkey(secret_packages[1], received_package[1])

# The subsequent signing phase is the same as above with signing_shares as the secret.
```

### Share repair

Using `FROST::Repairable` module, you can repair existing (or new) participant's share with the cooperation of T participants.

```ruby
ctx = FROST::Context.new(ECDSA::Group::Secp256k1, FROST::Type::RFC9591)
dealer = FROST::SigningKey.generate(ctx)

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
  participant_received_values << FROST::Repairable.step2(ctx, values)
end

# Participant can get his share.
repair_share = FROST::Repairable.step3(ctx, 2, participant_received_values)
```
