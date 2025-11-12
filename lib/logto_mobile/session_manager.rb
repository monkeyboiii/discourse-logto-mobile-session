# frozen_string_literal: true

require 'addressable/uri'

module LogtoMobile
  class SessionManager
    def initialize(controller)
      @controller = controller
    end

    # Create Discourse session for user and return cookie details
    def create_session(user)
      # Use Discourse's built-in session creation
      @controller.log_on_user(user)

      # Get session cookie details
      session_cookie_name = '_forum_session'
      session_cookie_value = @controller.request.cookie_jar.encrypted[session_cookie_name]

      # Determine cookie domain
      cookie_domain = extract_cookie_domain

      # Calculate expiration
      ttl_seconds = SiteSetting.logto_mobile_session_cookie_ttl
      expires_at = Time.now + ttl_seconds.seconds

      {
        name: session_cookie_name,
        value: session_cookie_value,
        domain: cookie_domain,
        path: '/',
        expires_at: expires_at.iso8601,
        secure: Rails.env.production?,
        http_only: true,
        same_site: 'Lax'
      }
    end

    # Destroy session
    def destroy_session
      @controller.log_off_user
    end

    private

    def extract_cookie_domain
      forced_domain = SiteSetting.force_hostname.presence
      forced_domain ||= GlobalSetting.force_hostname if GlobalSetting.respond_to?(:force_hostname)
      return forced_domain if forced_domain.present?

      request = @controller.request
      host = request&.host.presence || Discourse.current_hostname

      if Rails.env.production? && host.present? && host !~ /localhost|127\.0\.0\.1/
        begin
          domain = Addressable::URI.parse("https://#{host}").domain
        rescue Addressable::URI::InvalidURIError
          domain = nil
        end

        return ".#{domain}" if domain.present?
      end

      host
    end
  end
end
