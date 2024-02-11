require 'spec_helper'

RSpec.describe FROST::SigningKey do

  describe "#new" do
    context 'valid key range' do
      it do
        expect{described_class.generate(ECDSA::Group::Secp256k1)}.not_to raise_error
      end
    end
    context 'invalid key range' do
      it do
        expect{described_class.new(0)}.to raise_error(ArgumentError, "Invalid scalar range.")
        expect{described_class.new(ECDSA::Group::Secp256k1.order)}.to raise_error(ArgumentError, "Invalid scalar range.")
      end
    end
  end
end