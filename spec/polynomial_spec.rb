require 'spec_helper'

RSpec.describe FROST::Polynomial do

  let(:group) { ECDSA::Group::Secp256k1 }

  describe "#from_secret" do
    let(:secret) { SecureRandom.random_number(group.order - 1) }
    it do
      poly = described_class.from_secret(secret, 3, group)
      expect(poly.coefficients.length).to eq(4)
      expect(poly.coefficients.last).to eq(secret)
    end

    context "invalid degree" do
      it do
        expect{described_class.from_secret(secret, 0, group)}.
          to raise_error(ArgumentError, "degree must be greater than or equal to 1.")
      end
    end
  end

  describe "#new" do
    it do
      expect{described_class.new([1, 2], group)}.not_to raise_error
    end

    context "degree less than 1" do
      it do
        expect{described_class.new([1], group)}.
          to raise_error(ArgumentError, "Two or more coefficients are required.")
      end
    end
  end
end