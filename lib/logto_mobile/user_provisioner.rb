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
      email = @user_info[:email].downcase.strip

      # Match by email (including staged users)
      user = User.with_email(email).first

      # If staged, convert to real user
      if user&.staged?
        Rails.logger.info(
          "[LogtoMobileSession] Converting staged user to real user: #{user.username}",
        )
        user.active = false
        user.unstage!
        user.save!
      end

      return user if user

      # Fallback: check by custom field (Logto sub)
      user_id = UserCustomField.where(name: "logto_sub", value: @user_info[:sub]).first&.user_id
      user_id ? User.find_by(id: user_id) : nil
    end

    def create_new_user
      # Generate unique username
      username = ensure_unique_username(@user_info[:username])

      user =
        User.new(
          email: @user_info[:email],
          username: username,
          name: @user_info[:name] || username,
          active: true, # Auto-activate since Logto pre-verified
          approved: SiteSetting.logto_mobile_session_auto_approve_users,
          trust_level: TrustLevel[0],
          staged: false,
        )

      # Set a random secure password (user won't use it, always via OIDC)
      user.password = SecureRandom.hex(32)

      user.save!

      # Store Logto identifier
      user.custom_fields["logto_sub"] = @user_info[:sub]
      user.custom_fields["logto_email_verified"] = @user_info[:email_verified]
      user.save_custom_fields(true)

      # Create or update associated account
      ensure_user_association(user)

      # Sync avatar
      sync_avatar(user)

      # Sync profile (bio, location)
      sync_profile(user)

      user
    end

    def update_user_info(user)
      # Update name if changed
      if @user_info[:name].present? && user.name != @user_info[:name]
        user.name = @user_info[:name]
        user.save!
      end

      # Update custom fields
      user.custom_fields["logto_sub"] = @user_info[:sub]
      user.custom_fields["logto_email_verified"] = @user_info[:email_verified]
      user.custom_fields["logto_last_auth"] = Time.zone.now.iso8601
      user.save_custom_fields(true)

      # Ensure association exists and is up to date
      ensure_user_association(user)

      # Sync avatar
      sync_avatar(user)

      # Sync profile
      sync_profile(user)
    end

    def ensure_unique_username(base_username)
      return generate_random_username if base_username.blank?

      # Sanitize username
      username = base_username.gsub(/[^a-z0-9_-]/i, "_").slice(0, 20)

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

    # Ensures UserAssociatedAccount exists and is properly linked
    # Handles cleanup of duplicate associations
    def ensure_user_association(user)
      # CRITICAL: Destroy any existing associations for this user with 'oidc' provider
      # This prevents unique constraint violations when users switch Logto accounts
      UserAssociatedAccount.where(user: user, provider_name: "oidc").destroy_all

      # Find or initialize association by provider_uid
      association =
        UserAssociatedAccount.find_or_initialize_by(
          provider_name: "oidc",
          provider_uid: @user_info[:sub],
        )

      # Link to user
      association.user = user

      # Populate all required fields per schema
      association.info = {
        email: @user_info[:email],
        name: @user_info[:name],
        picture: @user_info[:picture],
      }

      association.credentials = {} # Empty for now, can store token metadata later

      association.extra = {
        email_verified: @user_info[:email_verified],
        created_via: "mobile_session_exchange",
      }

      association.last_used = Time.zone.now

      association.save!

      Rails.logger.info(
        "[LogtoMobileSession] Association ensured for user #{user.id} with provider_uid #{@user_info[:sub]}",
      )
    end

    # Syncs avatar from Logto, respecting settings
    def sync_avatar(user)
      return if @user_info[:picture].blank?

      # Respect auth_overrides_avatar setting (official OIDC pattern)
      if user.user_avatar&.custom_upload_id.present? && !SiteSetting.auth_overrides_avatar
        Rails.logger.info(
          "[LogtoMobileSession] Skipping avatar sync - user has custom avatar and override disabled",
        )
        return
      end

      Jobs.enqueue(
        :download_avatar_from_url,
        url: @user_info[:picture],
        user_id: user.id,
        override_gravatar: false,
      )

      Rails.logger.info("[LogtoMobileSession] Enqueued avatar download for user #{user.id}")
    end

    # Syncs profile information (bio, location) from Logto
    def sync_profile(user)
      return if @user_info[:bio].blank? && @user_info[:location].blank?

      profile = user.user_profile

      # Only update if fields are blank (don't override existing data)
      profile.bio_raw = @user_info[:bio] if @user_info[:bio].present? && profile.bio_raw.blank?

      if @user_info[:location].present? && profile.location.blank?
        profile.location = @user_info[:location]
      end

      profile.save if profile.changed?

      Rails.logger.info("[LogtoMobileSession] Profile synced for user #{user.id}")
    end
  end
end
