module FROST
  # Participant commitment
  class Commitments

    attr_reader :identifier
    attr_reader :hiding
    attr_reader :binding

    # Constructor
    # @param [Integer] identifier Identifier of participant.
    # @param [ECDSA::Point] hiding Commitment point.
    # @param [ECDSA::Point] binding Commitment point.
    def initialize(identifier, hiding, binding)
      raise ArgumentError, "id must be Integer." unless identifier.is_a?(Integer)
      raise ArgumentError, "id must be greater than 0." if identifier < 1
      raise ArgumentError, "hiding must be ECDSA::Point." unless hiding.is_a?(ECDSA::Point)
      raise ArgumentError, "binding must be ECDSA::Point." unless binding.is_a?(ECDSA::Point)

      @identifier = identifier
      @hiding = hiding
      @binding = binding
    end

    def encode
      id = FROST.encode_identifier(identifier, hiding.group)
      id + [hiding.to_hex + binding.to_hex].pack("H*")
    end

    # Encodes a list of participant commitments into a byte string
    # @param [Array] commitment_list The list of FROST::Commitments
    # @return [String] The encoded byte string.
    def self.encode_group_commitment(commitment_list)
      commitment_list.map(&:encode).join
    end
  end
end
