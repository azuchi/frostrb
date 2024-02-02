require 'spec_helper'

RSpec.describe FROST::Polynomial do

  describe "#from_secret" do
    let(:group) { ECDSA::Group::Secp256k1 }
    let(:secret) { SecureRandom.random_number(group.order - 1) }
    it do
      poly = described_class.from_secret(secret, 3, group)
      expect(poly.coefficients.length).to eq(4)
      expect(poly.coefficients.last).to eq(secret)
    end

    context "invalid degree" do
      it do
        expect{described_class.from_secret(secret, 1, group)}.
          to raise_error(ArgumentError, "degree must be greater than or equal to 2")
      end
    end
  end

end