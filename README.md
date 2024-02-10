# FROST (Flexible Round-Optimised Schnorr Threshold signatures) for Ruby [![Build Status](https://github.com/azuchi/frostrb/actions/workflows/main.yml/badge.svg?branch=master)](https://github.com/azuchi/frostrb/actions/workflows/main.yml)

This library is ruby implementations of ['Two-Round Threshold Schnorr Signatures with FROST'](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/).

Note: This library has not been security audited and tested widely, so should not be used in production.

The cipher suites currently supported by this library are:

* [secp256k1, SHA-256](https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-frostsecp256k1-sha-256)
* [P-256, SHA-256](https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-14.html#name-frostp-256-sha-256) 

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

group = ECDSA::Group::Secp256k1

# Dealer generate secret.
secret = FROST::SigningKey.generate(group)
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
sig_share1 = FROST.sign(share1, group_pubkey, [hiding_nonce1, binding_nonce1], msg, commitment_list)
sig_share3 = FROST.sign(share3, group_pubkey, [hiding_nonce3, binding_nonce3], msg, commitment_list)

# verify signature share
FROST.verify_share(1, share1.to_point, sig_share1, commitment_list, group_pubkey, msg)
FROST.verify_share(3, share3.to_point, sig_share3, commitment_list, group_pubkey, msg)

# Aggregation
sig = FROST.aggregate(commitment_list, msg, group_pubkey, [sig_share1, sig_share3])

# verify final signature
FROST.verify(sig, group_pubkey, msg)
```
