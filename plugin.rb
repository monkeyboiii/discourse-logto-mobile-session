# frozen_string_literal: true

# name: discourse-logto-mobile-session
# about: Exchange Logto OIDC access tokens for Discourse session cookies
# version: 1.0.0
# authors: monkeyboiii
# url: https://github.com/monkeyboiii/discourse-logto-mobile-session
# required_version: 2.7.0

enabled_site_setting :logto_mobile_session_enabled

# Define plugin namespace early so files loaded before initialization can reference it
module ::LogtoMobile
  PLUGIN_NAME = "discourse-logto-mobile-session"

  class Error < StandardError; end
  class ValidationError < Error; end
  class ProvisioningError < Error; end
end

after_initialize do
  # Validate OIDC prerequisite
  unless SiteSetting.openid_connect_enabled
    Rails.logger.warn "[LogtoMobileSession] OpenID Connect must be enabled for mobile session exchange"
  end

  # Load dependencies
  require_relative 'lib/logto_mobile/token_validator'
  require_relative 'lib/logto_mobile/user_provisioner'
  require_relative 'lib/logto_mobile/session_manager'
  require_relative 'app/controllers/logto_mobile/session_controller'

  # Add custom routes
  Discourse::Application.routes.append do
    scope "/api/auth", defaults: { format: :json } do
      post "mobile-session" => "logto_mobile/session#create"
      delete "mobile-session" => "logto_mobile/session#destroy"
      get "mobile-session/health" => "logto_mobile/session#health"
    end
  end

  # Add rate limiting for mobile session endpoint
  if defined?(RackAttack)
    Rack::Attack.throttle('mobile_session/ip', limit: 10, period: 1.minute) do |req|
      req.ip if req.path == '/api/auth/mobile-session' && req.post?
    end
  end
end
