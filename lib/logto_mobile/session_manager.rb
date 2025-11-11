# frozen_string_literal: true

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
      session_cookie_value = @controller.cookies.encrypted[session_cookie_name]

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
      # Use Discourse's configured cookie domain if set
      if SiteSetting.respond_to?(:cookies_domain) && SiteSetting.cookies_domain.present?
        return SiteSetting.cookies_domain
      end

      # Fall back to request host
      request = @controller.request
      host = request.host

      # For production, use root domain (e.g., .example.com)
      if Rails.env.production? && !host.match?(/localhost|127\.0\.0\.1/)
        parts = host.split('.')
        return ".#{parts.last(2).join('.')}" if parts.length >= 2
      end

      host
    end
  end
end