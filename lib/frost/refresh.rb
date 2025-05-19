module FROST
  module Refresh

    module_function

    # Refresh current_share using +refresh_share+.
    # @param [FROST::SecretShare] current_share
    # @param [FROST::SecretShare] refresh_share
    # @raise [ArgumentError]
    #
    def refresh_share(current_share, refresh_share)
      raise ArgumentError, "current_share must be FROST::SecretShare." unless current_share.is_a?(FROST::SecretShare)
      raise ArgumentError, "refresh_share must be FROST::SecretShare." unless refresh_share.is_a?(FROST::SecretShare)
      raise ArgumentError, "identifier mismatch." unless current_share.identifier == refresh_share.identifier

      current_share + refresh_share
    end

  end
end