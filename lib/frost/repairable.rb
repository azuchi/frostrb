module FROST
  # Implements the Repairable Threshold Scheme (RTS) from <https://eprint.iacr.org/2017/1155>
  module Repairable
    module_function

    # Step 1 for RTS.
    # Each helper computes delta_i,j for other helpers.
    # @param [Array] helpers Array of helper's identifier.
    # @param [Integer] participant Identifier of the participant whose shares you want to restore.
    # @param [FROST::SecretShare] share Share of participant running this process.
    # @return [Hash] Hash with helper ID as key and value as delta value.
    def step1(helpers, participant, share)
      raise ArgumentError, "helpers must be greater than 1." if helpers.length < 2
      raise ArgumentError, "participant must be greater than 1." if participant < 1
      raise ArgumentError, "helpers has duplicate identifier." unless helpers.uniq.length == helpers.length
      raise ArgumentError, "helpers contains same identifier with participant." if helpers.include?(participant)

      field = ECDSA::PrimeField.new(share.group.order)
      random_values = (helpers.length - 1).times.map { SecureRandom.random_number(share.group.order - 1) }

      # compute last random value
      ## Calculate Lagrange Coefficient for helper_i
      zeta_i = Polynomial.derive_interpolating_value(helpers, share.identifier, share.group, x: participant)
      lhs = field.mod(zeta_i * share.share)
      # last random value
      last = field.mod(lhs - random_values.sum)
      random_values << last

      helpers.zip(random_values).to_h
    end

    # Step 2 for RTS.
    # Each helper sum received delta values from other helpers.
    # @param [FROST::Context] context
    # @param [Array] step1_values Array of delta values.
    # @return [Integer] Sum of delta values.
    def step2(context, step1_values)
      raise ArgumentError, "context must be FROST::Context." unless context.is_a?(FROST::Context)

      field = ECDSA::PrimeField.new(context.group.order)
      field.mod(step1_values.sum)
    end

    # Participant compute own share with received sum of delta value.
    # @param [FROST::Context] context
    # @param [Integer] identifier Identifier of the participant whose shares you want to restore.
    # @param [Array] step2_results Array of Step 2 results received from other helpers.
    # @return
    def step3(context, identifier, step2_results)
      raise ArgumentError, "context must be FROST::Context." unless context.is_a?(FROST::Context)

      field = ECDSA::PrimeField.new(context.group.order)
      FROST::SecretShare.new(context, identifier, field.mod(step2_results.sum))
    end
  end
end
