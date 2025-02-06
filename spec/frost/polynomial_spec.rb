require 'spec_helper'

RSpec.describe FROST::Polynomial do

  let(:ctx) { FROST::Context.new(ECDSA::Group::Secp256k1, FROST::Type::RFC9591) }

  describe "#from_secret" do
    let(:secret) { SecureRandom.random_number(ctx.group.order - 1) }
    it do
      poly = described_class.from_secret(ctx, secret, 3)
      expect(poly.coefficients.length).to eq(4)
      expect(poly.coefficients.first).to eq(secret)
    end

    context "invalid degree" do
      it do
        expect{described_class.from_secret(ctx, secret, 0)}.
          to raise_error(ArgumentError, "degree must be greater than or equal to 1.")
      end
    end
  end

  describe "#new" do
    it do
      expect{described_class.new(ctx, [1, 2])}.not_to raise_error
    end

    context "degree less than 1" do
      it do
        expect{described_class.new(ctx, [1])}.
          to raise_error(ArgumentError, "Two or more coefficients are required.")
      end
    end
  end
end