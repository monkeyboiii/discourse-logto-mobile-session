# frozen_string_literal: true

module LogtoMobile
  class UserProvisioner
    def initialize(user_info)
      @user_info = user_info
    end

    # Find existing user or create new one
    def provision
      user = find_existing_user
      
      if user
        Rails.logger.info("[LogtoMobileSession] Found existing user: #{user.username} (#{user.id})")
        update_user_info(user)
      else
        user = create_new_user
        Rails.logger.info("[LogtoMobileSession] Created new user: #{user.username} (#{user.id})")
      end

      user
    rescue ActiveRecord::RecordInvalid => e
      Rails.logger.error("[LogtoMobileSession] User provisioning failed: #{e.message}")
      raise ProvisioningError, "Failed to provision user: #{e.message}"
    end

    private

    def find_existing_user
      # Match by email (primary identifier)
      user = User.find_by_email(@user_info[:email])
      return user if user

      # Also check by custom field (Logto sub)
      user_id = UserCustomField.where(name: 'logto_sub', value: @user_info[:sub]).first&.user_id
      user_id ? User.find_by(id: user_id) : nil
    end

    def create_new_user
      # Generate unique username
      username = ensure_unique_username(@user_info[:username])

      user = User.new(
        email: @user_info[:email],
        username: username,
        name: @user_info[:name] || username,
        active: true, # Auto-activate since Logto pre-verified
        approved: SiteSetting.logto_mobile_session_auto_approve_users,
        trust_level: TrustLevel[0],
        staged: false
      )

      # Set a random secure password (user won't use it, always via OIDC)
      user.password = SecureRandom.hex(32)

      user.save!

      # Store Logto identifier
      user.custom_fields['logto_sub'] = @user_info[:sub]
      user.custom_fields['logto_email_verified'] = @user_info[:email_verified]
      user.save_custom_fields(true)

      # REVIEW: TODO: May very much wait till later when actual user complains
      # about incosistent email vs OpenID Coonect email.

      # Create associated account record for OIDC
      UserAssociatedAccount.create!(
        provider_name: 'oidc',
        provider_uid: @user_info[:sub],
        user_id: user.id,
        extra: {
          email: @user_info[:email],
          name: @user_info[:name],
          created_via: 'mobile_session_exchange'
        }.to_json
      )

      # Set avatar if provided
      if @user_info[:picture].present?
        Jobs.enqueue(:download_avatar_from_url, 
          url: @user_info[:picture], 
          user_id: user.id,
          override_gravatar: false
        )
      end

      user
    end

    def update_user_info(user)
      # Update name if changed
      if @user_info[:name].present? && user.name != @user_info[:name]
        user.name = @user_info[:name]
        user.save!
      end

      # TODO: More custome fields here
      # Update Logto fields
      user.custom_fields['logto_sub'] = @user_info[:sub]
      user.custom_fields['logto_email_verified'] = @user_info[:email_verified]
      user.custom_fields['logto_last_auth'] = Time.now.iso8601
      user.save_custom_fields(true)
    end

    def ensure_unique_username(base_username)
      return generate_random_username if base_username.blank?

      # Sanitize username
      username = base_username.gsub(/[^a-z0-9_-]/i, '_').slice(0, 20)
      
      return username unless User.exists?(username: username)

      # Append numbers until unique
      counter = 1
      loop do
        candidate = "#{username}#{counter}"
        return candidate unless User.exists?(username: candidate)
        counter += 1
        raise ProvisioningError, "Could not generate unique username" if counter > 100
      end
    end

    def generate_random_username
      "user_#{SecureRandom.hex(8)}"
    end
  end
end