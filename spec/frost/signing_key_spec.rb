require 'spec_helper'

RSpec.describe FROST::SigningKey do

  let(:ctx) { FROST::Context.new(ECDSA::Group::Secp256k1, FROST::Type::RFC9591) }

  describe "#new" do
    context 'valid key range' do
      it do
        expect{described_class.generate(ctx)}.not_to raise_error
      end
    end
    context 'invalid key range' do
      it do
        expect{described_class.new(ctx, 0)}.to raise_error(ArgumentError, "Invalid scalar range.")
        expect{described_class.new(ctx, ECDSA::Group::Secp256k1.order)}.to raise_error(ArgumentError, "Invalid scalar range.")
      end
    end
  end
end