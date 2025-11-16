# frozen_string_literal: true

require "addressable/uri"

module LogtoMobile
  class SessionManager
    def initialize(controller)
      @controller = controller
    end

    # Create Discourse session for user and return cookie details
    def create_session(user)
      # Use Discourse's built-in session creation
      @controller.log_on_user(user)

      # Determine cookie domain
      cookie_domain = extract_cookie_domain

      # Calculate expiration based on Discourse's session settings
      expires_at =
        if SiteSetting.persistent_sessions
          SiteSetting.maximum_session_age.hours.from_now
        else
          nil # Session cookie (expires when browser closes)
        end

      # Access controller request's cookie jar (where new cookies are staged)
      cookie_jar = @controller.request.cookie_jar

      # Get the _t auth token cookie (primary authentication cookie)
      auth_token_cookie = cookie_jar.encrypted["_t"]

      # Get the Rails session cookie (if present in response)
      session_cookie = cookie_jar.encrypted["_forum_session"]

      {
        auth_token: {
          name: "_t",
          value: auth_token_cookie,
          domain: cookie_domain,
          path: "/",
          expires_at: expires_at&.iso8601,
          secure: Rails.env.production?,
          http_only: true,
          same_site: "Lax",
        },
        session_cookie: {
          name: "_forum_session",
          value: session_cookie,
          domain: cookie_domain,
          path: "/",
          expires_at: expires_at&.iso8601,
          secure: Rails.env.production?,
          http_only: true,
          same_site: "Lax",
        },
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

      # Return the full domain, not the apex domain
      # This matches browser behavior (e.g., forum.dirtbikechina.com not .dirtbikechina.com)
      host
    end
  end
end
