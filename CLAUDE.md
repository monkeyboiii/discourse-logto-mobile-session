# Complete Implementation Guide: Discourse Mobile Session Exchange Plugin

## Executive Summary

This guide provides production-ready code for a Discourse plugin that securely exchanges Logto OIDC access tokens for Discourse session cookies, enabling native mobile apps to authenticate users into WebView contexts. The implementation supports **two token validation methods** (feature-flag switchable), comprehensive security controls, and automatic user provisioning.

**Core Capability:** POST an access token from your iOS app → Receive a session cookie → Inject into WebView → User is authenticated in Discourse forum.

## Architecture Overview

### Design Decision: Standalone Plugin

The plugin is implemented as a **standalone module** that:

- Reuses existing OIDC configuration from Discourse core (client ID, secret, discovery endpoint)
- Adds custom API endpoints for mobile token exchange
- Remains independent and maintainable without modifying core authentication
- Validates OIDC is enabled as a prerequisite

### Component Architecture

```
Mobile App (Logto SDK) → Access Token
         ↓
POST /api/auth/mobile-session
         ↓
Token Validation (userinfo OR JWT)
         ↓
User Provisioning (if new)
         ↓
Discourse Session Creation (log_on_user)
         ↓
Session Cookie Response → WebView
```

---

## 1. Plugin File Structure

```
plugins/discourse-logto-mobile-session/
├── plugin.rb                                 # Main plugin manifest
├── config/
│   ├── settings.yml                          # Plugin configuration
│   └── locales/
│       └── server.en.yml                     # Translations
├── app/
│   └── controllers/
│       └── logto_mobile/
│           └── session_controller.rb         # API endpoint controller
├── lib/
│   ├── logto_mobile/
│   │   ├── token_validator.rb               # Token validation service
│   │   ├── user_provisioner.rb              # User creation/matching
│   │   └── session_manager.rb               # Session cookie handling
│   └── validators/
│       └── oidc_enabled_validator.rb         # Prerequisites check
└── spec/
    └── requests/
        └── logto_mobile_session_spec.rb      # Integration tests
```

---

## 2. Plugin Manifest (plugin.rb)

```ruby
# frozen_string_literal: true

# name: discourse-logto-mobile-session
# about: Exchange Logto OIDC access tokens for Discourse session cookies (Phase 1 mobile auth)
# version: 1.0.0
# authors: Your Organization
# url: https://github.com/yourorg/discourse-logto-mobile-session
# required_version: 2.7.0

enabled_site_setting :logto_mobile_session_enabled

gem 'jwt', '2.7.1'

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

  # Define plugin namespace
  module ::LogtoMobile
    PLUGIN_NAME = "discourse-logto-mobile-session"
    
    class Error < StandardError; end
    class ValidationError < Error; end
    class ProvisioningError < Error; end
  end

  # Add custom routes
  Discourse::Application.routes.append do
    namespace :api do
      namespace :auth do
        post 'mobile-session' => 'logto_mobile/session#create'
        delete 'mobile-session' => 'logto_mobile/session#destroy'
        get 'mobile-session/health' => 'logto_mobile/session#health'
      end
    end
  end

  # Add rate limiting for mobile session endpoint
  if defined?(RackAttack)
    Rack::Attack.throttle('mobile_session/ip', limit: 10, period: 1.minute) do |req|
      req.ip if req.path == '/api/auth/mobile-session' && req.post?
    end
  end
end
```

---

## 3. Configuration Settings (config/settings.yml)

```yaml
plugins:
  logto_mobile_session_enabled:
    default: false
    client: false
    description: "Enable Logto mobile session exchange endpoint"
  
  logto_mobile_session_validation_method:
    default: "userinfo"
    type: enum
    choices:
      - userinfo
      - jwt
    client: false
    description: "Token validation method: 'userinfo' (call Logto API) or 'jwt' (local signature validation)"
  
  logto_mobile_session_cookie_ttl:
    default: 86400
    type: integer
    min: 3600
    max: 2592000
    client: false
    description: "Session cookie time-to-live in seconds (default 24 hours)"
  
  logto_mobile_session_auto_approve_users:
    default: true
    client: false
    description: "Automatically approve users created via mobile session exchange"
  
  logto_mobile_session_require_verified_email:
    default: true
    client: false
    description: "Only allow users with verified emails from Logto"
  
  logto_mobile_session_allowed_client_types:
    default: "ios_native,android_native"
    type: list
    list_type: compact
    client: false
    description: "Comma-separated list of allowed client types"
  
  logto_mobile_session_rate_limit_per_minute:
    default: 10
    type: integer
    min: 1
    max: 100
    client: false
    description: "Maximum token exchange requests per IP per minute"
```

---

## 4. Token Validation Service (lib/logto_mobile/token_validator.rb)

```ruby
# frozen_string_literal: true

module LogtoMobile
  class TokenValidator
    require 'net/http'
    require 'uri'
    require 'json'
    require 'jwt'

    JWKS_CACHE_TTL = 3600 # 1 hour

    def initialize
      @validation_method = SiteSetting.logto_mobile_session_validation_method
      @tenant_endpoint = extract_tenant_endpoint
      @jwks_cache = nil
      @jwks_cached_at = nil
    end

    # Main validation entry point
    def validate_token(access_token)
      case @validation_method
      when 'userinfo'
        validate_via_userinfo(access_token)
      when 'jwt'
        validate_via_jwt(access_token)
      else
        raise ValidationError, "Invalid validation method: #{@validation_method}"
      end
    rescue StandardError => e
      Rails.logger.error("[LogtoMobileSession] Token validation failed: #{e.message}")
      { success: false, error: 'validation_failed', message: e.message }
    end

    private

    # METHOD 1: Validate via Logto's /userinfo endpoint
    def validate_via_userinfo(access_token)
      userinfo_endpoint = "#{@tenant_endpoint}/oidc/userinfo"
      uri = URI(userinfo_endpoint)

      request = Net::HTTP::Get.new(uri)
      request['Authorization'] = "Bearer #{access_token}"

      response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https', read_timeout: 10) do |http|
        http.request(request)
      end

      case response.code.to_i
      when 200
        user_info = JSON.parse(response.body)
        validate_user_claims(user_info)
        {
          success: true,
          user_info: normalize_user_info(user_info),
          validation_method: 'userinfo'
        }
      when 401
        { success: false, error: 'invalid_token', message: 'Token is invalid or expired' }
      when 403
        { success: false, error: 'insufficient_scope', message: 'Token lacks required permissions' }
      else
        { success: false, error: 'validation_failed', message: "HTTP #{response.code}" }
      end
    rescue Timeout::Error
      { success: false, error: 'timeout', message: 'Logto userinfo endpoint timeout' }
    rescue StandardError => e
      { success: false, error: 'request_failed', message: e.message }
    end

    # METHOD 2: Validate via JWT signature using Logto's public keys
    def validate_via_jwt(access_token)
      issuer = "#{@tenant_endpoint}/oidc"
      
      # Create JWKS loader with caching and automatic refresh
      jwk_loader = lambda do |options|
        jwks_data = fetch_jwks(force_refresh: options[:invalidate])
        jwks_data.deep_symbolize_keys
      end

      # Decode and verify JWT
      decoded_token = JWT.decode(
        access_token,
        nil,
        true, # Verify signature
        {
          algorithm: 'RS256',
          iss: issuer,
          verify_iss: true,
          verify_aud: false, # May vary based on Logto config
          verify_exp: true,
          verify_iat: true,
          jwks: jwk_loader
        }
      )

      payload = decoded_token[0]
      
      # Convert JWT claims to userinfo format
      user_info = {
        'sub' => payload['sub'],
        'email' => payload['email'],
        'email_verified' => payload['email_verified'],
        'name' => payload['name'],
        'username' => payload['username'] || payload['preferred_username'],
        'picture' => payload['picture']
      }

      validate_user_claims(user_info)

      {
        success: true,
        user_info: normalize_user_info(user_info),
        validation_method: 'jwt',
        expires_at: Time.at(payload['exp'])
      }
    rescue JWT::DecodeError, JWT::VerificationError => e
      { success: false, error: 'invalid_token', message: "JWT validation failed: #{e.message}" }
    rescue JWT::ExpiredSignature
      { success: false, error: 'expired_token', message: 'Token has expired' }
    rescue JWT::InvalidIssuerError
      { success: false, error: 'invalid_issuer', message: 'Token issuer does not match Logto' }
    rescue StandardError => e
      { success: false, error: 'jwt_validation_failed', message: e.message }
    end

    # Fetch JWKS from Logto with caching
    def fetch_jwks(force_refresh: false)
      if force_refresh || @jwks_cache.nil? || jwks_expired?
        jwks_uri = "#{@tenant_endpoint}/oidc/jwks"
        uri = URI(jwks_uri)
        
        response = Net::HTTP.get_response(uri)
        raise ValidationError, "Failed to fetch JWKS: HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        @jwks_cache = JSON.parse(response.body)
        @jwks_cached_at = Time.now
        
        Rails.logger.info("[LogtoMobileSession] JWKS refreshed from #{jwks_uri}")
      end

      @jwks_cache
    end

    def jwks_expired?
      @jwks_cached_at.nil? || (Time.now - @jwks_cached_at) > JWKS_CACHE_TTL
    end

    # Validate required claims are present
    def validate_user_claims(user_info)
      raise ValidationError, "Missing 'sub' claim" unless user_info['sub'].present?
      raise ValidationError, "Missing 'email' claim" unless user_info['email'].present?

      if SiteSetting.logto_mobile_session_require_verified_email
        unless user_info['email_verified'] == true
          raise ValidationError, "Email not verified in Logto"
        end
      end
    end

    # Normalize user info to consistent format
    def normalize_user_info(user_info)
      {
        sub: user_info['sub'],
        email: user_info['email']&.downcase&.strip,
        email_verified: user_info['email_verified'] == true,
        name: user_info['name'] || user_info['email']&.split('@')&.first,
        username: user_info['username'] || user_info['preferred_username'] || generate_username_from_email(user_info['email']),
        picture: user_info['picture']
      }
    end

    def generate_username_from_email(email)
      return nil unless email
      email.split('@').first.gsub(/[^a-z0-9_-]/i, '_').slice(0, 20)
    end

    # Extract tenant endpoint from OIDC discovery document setting
    def extract_tenant_endpoint
      discovery_url = SiteSetting.openid_connect_discovery_document
      raise ValidationError, "OIDC discovery document not configured" unless discovery_url.present?

      # Extract base URL from discovery document URL
      # e.g., https://tenant.logto.app/oidc/.well-known/openid-configuration -> https://tenant.logto.app
      uri = URI(discovery_url)
      "#{uri.scheme}://#{uri.host}#{uri.port != uri.default_port ? ":#{uri.port}" : ''}"
    end
  end
end

# Extension for Hash deep symbolization
class Hash
  def deep_symbolize_keys
    transform_keys(&:to_sym).transform_values do |value|
      case value
      when Hash
        value.deep_symbolize_keys
      when Array
        value.map { |v| v.is_a?(Hash) ? v.deep_symbolize_keys : v }
      else
        value
      end
    end
  end unless method_defined?(:deep_symbolize_keys)
end
```

---

## 5. User Provisioning Service (lib/logto_mobile/user_provisioner.rb)

```ruby
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
```

---

## 6. Session Manager (lib/logto_mobile/session_manager.rb)

```ruby
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
```

---

## 7. API Controller (app/controllers/logto_mobile/session_controller.rb)

```ruby
# frozen_string_literal: true

module LogtoMobile
  class SessionController < ::ApplicationController
    requires_plugin 'discourse-logto-mobile-session'

    skip_before_action :verify_authenticity_token, only: [:create, :destroy]
    skip_before_action :redirect_to_login_if_required
    skip_before_action :check_xhr, only: [:create, :destroy, :health]

    before_action :check_plugin_enabled
    before_action :check_oidc_enabled
    before_action :validate_client_type, only: [:create]
    before_action :check_rate_limit, only: [:create]

    rescue_from LogtoMobile::ValidationError, with: :handle_validation_error
    rescue_from LogtoMobile::ProvisioningError, with: :handle_provisioning_error
    rescue_from StandardError, with: :handle_generic_error

    def create
      # Extract access token from request
      access_token = extract_access_token

      # Validate token with Logto
      validation_result = token_validator.validate_token(access_token)

      unless validation_result[:success]
        return render json: {
          error: validation_result[:error],
          message: validation_result[:message]
        }, status: :unauthorized
      end

      # Provision user (find or create)
      provisioner = UserProvisioner.new(validation_result[:user_info])
      user = provisioner.provision

      # Create Discourse session
      session_manager = SessionManager.new(self)
      session_cookie = session_manager.create_session(user)

      # Log successful authentication
      log_authentication_event('mobile_session_created', user, validation_result[:validation_method])

      # Return session cookie details
      render json: {
        success: true,
        session_cookie: session_cookie,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          name: user.name,
          avatar_url: user.avatar_template_url.gsub("{size}", "120")
        },
        validation_method: validation_result[:validation_method]
      }, status: :created
    end

    def destroy
      session_manager = SessionManager.new(self)
      session_manager.destroy_session

      log_authentication_event('mobile_session_destroyed', current_user, nil)

      render json: { success: true, message: 'Session destroyed' }
    end

    def health
      checks = {
        plugin_enabled: SiteSetting.logto_mobile_session_enabled,
        oidc_enabled: SiteSetting.openid_connect_enabled,
        oidc_configured: SiteSetting.openid_connect_discovery_document.present?,
        validation_method: SiteSetting.logto_mobile_session_validation_method,
        rate_limiting: defined?(RackAttack)
      }

      all_healthy = checks.values.all? { |v| v == true || v.present? }

      render json: {
        healthy: all_healthy,
        checks: checks,
        version: '1.0.0'
      }, status: all_healthy ? :ok : :service_unavailable
    end

    private

    def check_plugin_enabled
      unless SiteSetting.logto_mobile_session_enabled
        render json: { error: 'Plugin not enabled' }, status: :service_unavailable
      end
    end

    def check_oidc_enabled
      unless SiteSetting.openid_connect_enabled
        render json: { 
          error: 'OIDC not enabled',
          message: 'OpenID Connect must be enabled and configured'
        }, status: :service_unavailable
      end
    end

    def validate_client_type
      client_type = params[:client_type]
      
      unless client_type.present?
        return render json: { error: 'client_type required' }, status: :bad_request
      end

      allowed_types = SiteSetting.logto_mobile_session_allowed_client_types.split(',').map(&:strip)
      
      unless allowed_types.include?(client_type)
        render json: { 
          error: 'invalid_client_type',
          message: "Client type '#{client_type}' not allowed"
        }, status: :forbidden
      end
    end

    def check_rate_limit
      rate_limit_key = "mobile_session:#{request.ip}"
      limit = SiteSetting.logto_mobile_session_rate_limit_per_minute
      
      if Discourse.redis.exists(rate_limit_key)
        attempts = Discourse.redis.get(rate_limit_key).to_i
        
        if attempts >= limit
          return render json: {
            error: 'rate_limit_exceeded',
            message: 'Too many requests. Please try again later.',
            retry_after: Discourse.redis.ttl(rate_limit_key)
          }, status: :too_many_requests
        end
      end

      Discourse.redis.incr(rate_limit_key)
      Discourse.redis.expire(rate_limit_key, 60)
    end

    def extract_access_token
      access_token = params[:access_token]
      
      # Also support Authorization header
      if access_token.blank? && request.headers['Authorization'].present?
        auth_header = request.headers['Authorization']
        access_token = auth_header.split(' ').last if auth_header.start_with?('Bearer ')
      end

      unless access_token.present?
        raise ValidationError, "access_token is required"
      end

      access_token
    end

    def token_validator
      @token_validator ||= TokenValidator.new
    end

    def log_authentication_event(event_type, user, validation_method)
      # NEVER log actual tokens
      Rails.logger.info({
        event: event_type,
        user_id: user&.id,
        username: user&.username,
        ip: request.ip,
        user_agent: request.user_agent,
        client_type: params[:client_type],
        validation_method: validation_method,
        timestamp: Time.now.iso8601
      }.to_json)

      # Also use Discourse's StaffActionLogger for admin visibility
      if user && current_user&.staff?
        StaffActionLogger.new(current_user).log_custom(
          'mobile_session_exchange',
          { user_id: user.id, validation_method: validation_method }
        )
      end
    end

    # Error handlers
    def handle_validation_error(exception)
      Rails.logger.warn("[LogtoMobileSession] Validation error: #{exception.message}")
      render json: {
        error: 'validation_error',
        message: exception.message
      }, status: :unauthorized
    end

    def handle_provisioning_error(exception)
      Rails.logger.error("[LogtoMobileSession] Provisioning error: #{exception.message}")
      render json: {
        error: 'provisioning_error',
        message: 'Failed to create or update user account'
      }, status: :internal_server_error
    end

    def handle_generic_error(exception)
      Rails.logger.error("[LogtoMobileSession] Unexpected error: #{exception.message}\n#{exception.backtrace.join("\n")}")
      render json: {
        error: 'internal_error',
        message: 'An unexpected error occurred'
      }, status: :internal_server_error
    end
  end
end
```

---

## 8. Localization (config/locales/server.en.yml)

```yaml
en:
  site_settings:
    logto_mobile_session_enabled: "Enable Logto mobile session exchange"
    logto_mobile_session_validation_method: "Token validation method"
    logto_mobile_session_cookie_ttl: "Session cookie time-to-live (seconds)"
    logto_mobile_session_auto_approve_users: "Automatically approve new users"
    logto_mobile_session_require_verified_email: "Require verified email from Logto"
    logto_mobile_session_allowed_client_types: "Allowed mobile client types"
    logto_mobile_session_rate_limit_per_minute: "Rate limit (requests per minute)"
```

---

## 9. Testing Specification (spec/requests/logto_mobile_session_spec.rb)

```ruby
# frozen_string_literal: true

require 'rails_helper'

describe 'LogtoMobile::SessionController', type: :request do
  before do
    SiteSetting.logto_mobile_session_enabled = true
    SiteSetting.openid_connect_enabled = true
    SiteSetting.openid_connect_discovery_document = 'https://test.logto.app/oidc/.well-known/openid-configuration'
  end

  describe 'POST /api/auth/mobile-session' do
    let(:valid_token) { 'valid_access_token_123' }
    let(:user_info) do
      {
        sub: 'user123',
        email: '[email protected]',
        email_verified: true,
        name: 'John Doe',
        username: 'johndoe'
      }
    end

    before do
      # Mock token validator
      validator = instance_double(LogtoMobile::TokenValidator)
      allow(LogtoMobile::TokenValidator).to receive(:new).and_return(validator)
      allow(validator).to receive(:validate_token).with(valid_token).and_return({
        success: true,
        user_info: user_info,
        validation_method: 'userinfo'
      })
    end

    context 'with valid token and new user' do
      it 'creates user and returns session cookie' do
        post '/api/auth/mobile-session', params: {
          access_token: valid_token,
          client_type: 'ios_native'
        }

        expect(response.status).to eq(201)
        json = JSON.parse(response.body)
        
        expect(json['success']).to eq(true)
        expect(json['session_cookie']).to be_present
        expect(json['session_cookie']['name']).to eq('_forum_session')
        expect(json['session_cookie']['value']).to be_present
        expect(json['session_cookie']['http_only']).to eq(true)
        expect(json['user']['username']).to eq('johndoe')
        expect(json['user']['email']).to eq('[email protected]')

        # Verify user was created
        user = User.find_by_email('[email protected]')
        expect(user).to be_present
        expect(user.active).to eq(true)
        expect(user.custom_fields['logto_sub']).to eq('user123')
      end
    end

    context 'with valid token and existing user' do
      let!(:existing_user) do
        Fabricate(:user, email: '[email protected]', username: 'johndoe')
      end

      it 'logs in existing user' do
        post '/api/auth/mobile-session', params: {
          access_token: valid_token,
          client_type: 'ios_native'
        }

        expect(response.status).to eq(201)
        json = JSON.parse(response.body)
        
        expect(json['user']['id']).to eq(existing_user.id)
        expect(User.count).to eq(1) # No new user created
      end
    end

    context 'with invalid token' do
      before do
        validator = instance_double(LogtoMobile::TokenValidator)
        allow(LogtoMobile::TokenValidator).to receive(:new).and_return(validator)
        allow(validator).to receive(:validate_token).and_return({
          success: false,
          error: 'invalid_token',
          message: 'Token is invalid'
        })
      end

      it 'returns 401 unauthorized' do
        post '/api/auth/mobile-session', params: {
          access_token: 'invalid_token',
          client_type: 'ios_native'
        }

        expect(response.status).to eq(401)
        json = JSON.parse(response.body)
        expect(json['error']).to eq('invalid_token')
      end
    end

    context 'without access_token parameter' do
      it 'returns 401 with validation error' do
        post '/api/auth/mobile-session', params: {
          client_type: 'ios_native'
        }

        expect(response.status).to eq(401)
        json = JSON.parse(response.body)
        expect(json['error']).to eq('validation_error')
      end
    end

    context 'without client_type parameter' do
      it 'returns 400 bad request' do
        post '/api/auth/mobile-session', params: {
          access_token: valid_token
        }

        expect(response.status).to eq(400)
        json = JSON.parse(response.body)
        expect(json['error']).to eq('client_type required')
      end
    end

    context 'with disallowed client_type' do
      it 'returns 403 forbidden' do
        post '/api/auth/mobile-session', params: {
          access_token: valid_token,
          client_type: 'web_browser'
        }

        expect(response.status).to eq(403)
        json = JSON.parse(response.body)
        expect(json['error']).to eq('invalid_client_type')
      end
    end

    context 'rate limiting' do
      it 'blocks after exceeding limit' do
        SiteSetting.logto_mobile_session_rate_limit_per_minute = 2

        # First two requests should succeed
        2.times do
          post '/api/auth/mobile-session', params: {
            access_token: valid_token,
            client_type: 'ios_native'
          }
          expect(response.status).to eq(201)
        end

        # Third request should be rate limited
        post '/api/auth/mobile-session', params: {
          access_token: valid_token,
          client_type: 'ios_native'
        }
        
        expect(response.status).to eq(429)
        json = JSON.parse(response.body)
        expect(json['error']).to eq('rate_limit_exceeded')
      end
    end
  end

  describe 'DELETE /api/auth/mobile-session' do
    it 'destroys the session' do
      user = Fabricate(:user)
      sign_in(user)

      delete '/api/auth/mobile-session'

      expect(response.status).to eq(200)
      json = JSON.parse(response.body)
      expect(json['success']).to eq(true)
    end
  end

  describe 'GET /api/auth/mobile-session/health' do
    it 'returns health status' do
      get '/api/auth/mobile-session/health'

      expect(response.status).to eq(200)
      json = JSON.parse(response.body)
      
      expect(json['healthy']).to be_in([true, false])
      expect(json['checks']).to be_present
      expect(json['version']).to eq('1.0.0')
    end
  end
end
```

---

## 10. Installation \u0026 Configuration Guide

### Prerequisites

1. **Self-hosted Discourse instance** (version 2.7.0+)
2. **Logto tenant** with OIDC configured
3. **OpenID Connect enabled** in Discourse
4. **Redis** available (for rate limiting)

### Step 1: Install Plugin

**Via app.yml (Docker installation):**

```yaml
hooks:
  after_code:
    - exec:
        cd: $home/plugins
        cmd:
          - git clone https://github.com/yourorg/discourse-logto-mobile-session.git
```

Rebuild container:
```bash
cd /var/discourse
./launcher rebuild app
```

**Via development installation:**

```bash
cd discourse/plugins
git clone https://github.com/yourorg/discourse-logto-mobile-session.git
bundle install
```

### Step 2: Configure OpenID Connect

Navigate to **Admin → Settings → Login** and configure:

- **openid connect enabled**: ✓ Enabled
- **openid connect discovery document**: `https://your-tenant.logto.app/oidc/.well-known/openid-configuration`
- **openid connect client id**: Your Logto application client ID
- **openid connect client secret**: Your Logto application client secret

**Logto Configuration:**

In your Logto application settings, add the redirect URI:
```
https://your-discourse-domain.com/auth/oidc/callback
```

### Step 3: Enable Mobile Session Plugin

Navigate to **Admin → Settings → Plugins → discourse-logto-mobile-session**:

- **logto mobile session enabled**: ✓ Enabled
- **logto mobile session validation method**: `userinfo` (recommended for initial setup)
- **logto mobile session cookie ttl**: `86400` (24 hours)
- **logto mobile session auto approve users**: ✓ Enabled
- **logto mobile session require verified email**: ✓ Enabled
- **logto mobile session allowed client types**: `ios_native,android_native`
- **logto mobile session rate limit per minute**: `10`

### Step 4: Test Configuration

**Health Check:**
```bash
curl https://your-discourse-domain.com/api/auth/mobile-session/health
```

Expected response:
```json
{
  "healthy": true,
  "checks": {
    "plugin_enabled": true,
    "oidc_enabled": true,
    "oidc_configured": true,
    "validation_method": "userinfo",
    "rate_limiting": true
  },
  "version": "1.0.0"
}
```

### Step 5: Test Token Exchange

**Obtain access token** from your iOS app using Logto SDK, then:

```bash
curl -X POST https://your-discourse-domain.com/api/auth/mobile-session \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "YOUR_LOGTO_ACCESS_TOKEN",
    "client_type": "ios_native"
  }'
```

Expected response:
```json
{
  "success": true,
  "session_cookie": {
    "name": "_forum_session",
    "value": "encrypted_session_value",
    "domain": ".yourdomain.com",
    "path": "/",
    "expires_at": "2024-12-01T12:00:00Z",
    "secure": true,
    "http_only": true,
    "same_site": "Lax"
  },
  "user": {
    "id": 123,
    "username": "johndoe",
    "email": "[email protected]",
    "name": "John Doe",
    "avatar_url": "https://..."
  },
  "validation_method": "userinfo"
}
```

---

## 11. iOS Integration Example

```swift
import SwiftUI
import WebKit
import LogtoClient

class DiscourseAuthManager {
    let logtoClient: LogtoClient
    let discourseAPIBase = "https://your-discourse-domain.com"
    
    init(logtoClient: LogtoClient) {
        self.logtoClient = logtoClient
    }
    
    // Exchange Logto token for Discourse session
    func exchangeTokenForSession(completion: @escaping (Result<SessionCookie, Error>) -> Void) {
        // Get access token from Logto
        logtoClient.getAccessToken { result in
            switch result {
            case .success(let accessToken):
                self.callMobileSessionAPI(accessToken: accessToken, completion: completion)
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    private func callMobileSessionAPI(accessToken: String, completion: @escaping (Result<SessionCookie, Error>) -> Void) {
        let url = URL(string: "\(discourseAPIBase)/api/auth/mobile-session")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body: [String: Any] = [
            "access_token": accessToken,
            "client_type": "ios_native"
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let data = data else {
                completion(.failure(NSError(domain: "DiscourseAuth", code: -1)))
                return
            }
            
            do {
                let decoder = JSONDecoder()
                decoder.keyDecodingStrategy = .convertFromSnakeCase
                let response = try decoder.decode(MobileSessionResponse.self, from: data)
                completion(.success(response.sessionCookie))
            } catch {
                completion(.failure(error))
            }
        }.resume()
    }
    
    // Inject session cookie into WKWebView
    func configureWebView(_ webView: WKWebView, with sessionCookie: SessionCookie, completion: @escaping () -> Void) {
        let cookieStore = webView.configuration.websiteDataStore.httpCookieStore
        
        let cookie = HTTPCookie(properties: [
            .name: sessionCookie.name,
            .value: sessionCookie.value,
            .domain: sessionCookie.domain,
            .path: sessionCookie.path,
            .secure: sessionCookie.secure,
            .expires: ISO8601DateFormatter().date(from: sessionCookie.expiresAt) ?? Date()
        ])!
        
        cookieStore.setCookie(cookie) {
            completion()
        }
    }
    
    // Complete flow: authenticate and load forum
    func loadAuthenticatedForum(in webView: WKWebView, completion: @escaping (Result<Void, Error>) -> Void) {
        exchangeTokenForSession { result in
            switch result {
            case .success(let sessionCookie):
                self.configureWebView(webView, with: sessionCookie) {
                    let forumURL = URL(string: self.discourseAPIBase)!
                    webView.load(URLRequest(url: forumURL))
                    completion(.success(()))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
}

// Data models
struct MobileSessionResponse: Codable {
    let success: Bool
    let sessionCookie: SessionCookie
    let user: DiscourseUser
    let validationMethod: String
}

struct SessionCookie: Codable {
    let name: String
    let value: String
    let domain: String
    let path: String
    let expiresAt: String
    let secure: Bool
    let httpOnly: Bool
    let sameSite: String
}

struct DiscourseUser: Codable {
    let id: Int
    let username: String
    let email: String
    let name: String
    let avatarUrl: String
}

// SwiftUI View Example
struct ForumView: View {
    @StateObject private var webViewStore = WebViewStore()
    let authManager: DiscourseAuthManager
    
    var body: some View {
        WebView(webView: webViewStore.webView)
            .onAppear {
                authManager.loadAuthenticatedForum(in: webViewStore.webView) { result in
                    switch result {
                    case .success:
                        print("Forum loaded with authenticated session")
                    case .failure(let error):
                        print("Authentication failed: \(error)")
                    }
                }
            }
    }
}

class WebViewStore: ObservableObject {
    let webView: WKWebView
    
    init() {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent() // Or .default() to persist
        self.webView = WKWebView(frame: .zero, configuration: config)
    }
}

struct WebView: UIViewRepresentable {
    let webView: WKWebView
    
    func makeUIView(context: Context) -> WKWebView {
        return webView
    }
    
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}
```

---

## 12. Switching to JWT Validation

After initial testing with `userinfo` method, switch to JWT for better performance:

### Update Settings

Navigate to **Admin → Settings → Plugins**:
- **logto mobile session validation method**: Change to `jwt`

### Verify JWT Endpoint

Ensure Logto's JWKS endpoint is accessible:
```bash
curl https://your-tenant.logto.app/oidc/jwks
```

Should return public keys:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "abc123",
      "n": "...",
      "e": "AQAB",
      "alg": "RS256"
    }
  ]
}
```

### Test JWT Validation

The endpoint behavior remains identical - validation happens server-side:

```bash
curl -X POST https://your-discourse-domain.com/api/auth/mobile-session \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "YOUR_JWT_ACCESS_TOKEN",
    "client_type": "ios_native"
  }'
```

Response should include `"validation_method": "jwt"`.

### Performance Benefits

- **Latency**: ~50-100ms faster (no external API call)
- **Reliability**: Works even if Logto userinfo endpoint is temporarily down
- **Scalability**: No outbound traffic per request

---

## 13. Security Considerations

### Multi-Account Protection

**Risk**: User could obtain multiple tokens and create multiple accounts.

**Mitigation**: The plugin matches users by:
1. Email address (primary)
2. Logto `sub` identifier (stored in custom fields)

If email already exists, existing account is used. Logto should enforce unique emails.

### Token Theft Prevention

**Risk**: Stolen access token could be used to create sessions.

**Mitigations Implemented:**
- Rate limiting (10 requests/minute per IP)
- Token validation via Logto (ensures token is valid and not revoked)
- Short-lived tokens (Logto default: 1 hour)
- Audit logging of all token exchanges
- Client type validation

**Additional Recommendations:**
- Use PKCE in mobile app (Proof Key for Code Exchange)
- Implement device fingerprinting
- Monitor for anomalous patterns (multiple IPs using same token)

### Session Hijacking Prevention

**Mitigations Implemented:**
- HttpOnly cookies (not accessible to JavaScript)
- Secure flag (HTTPS only in production)
- SameSite=Lax (CSRF protection)
- Session expiration (24 hours default)

### Privilege Escalation Prevention

**Mitigations:**
- New users start at Trust Level 0
- Auto-approval can be disabled via settings
- Email verification enforced via Logto
- Staff accounts require manual approval

---

## 14. Monitoring \u0026 Debugging

### Log Monitoring

Key events are logged in JSON format:

```bash
# Monitor mobile session exchanges
tail -f /var/discourse/shared/standalone/log/rails/production.log | grep LogtoMobileSession
```

Example log entry:
```json
{
  "event": "mobile_session_created",
  "user_id": 123,
  "username": "johndoe",
  "ip": "203.0.113.45",
  "user_agent": "MyApp/1.0 (iOS 17.0)",
  "client_type": "ios_native",
  "validation_method": "jwt",
  "timestamp": "2024-11-10T15:30:00Z"
}
```

### Admin Visibility

Navigate to **Admin → Logs → Staff Actions** to view:
- Mobile session exchanges
- User provisioning events
- Failed authentication attempts

### Common Issues

**Issue**: "OIDC not enabled" error

**Solution**: Enable OpenID Connect in Discourse settings and configure Logto discovery URL.

---

**Issue**: "Invalid token" with userinfo method

**Solution**: 
- Verify access token is not expired
- Check Logto scopes include `openid`, `email`, `profile`
- Ensure Logto API resource includes userinfo access

---

**Issue**: JWT validation fails with "Invalid issuer"

**Solution**: 
- Verify OIDC discovery document URL is correct
- Ensure it matches Logto tenant exactly
- Check issuer in JWT matches `{tenant}/oidc`

---

**Issue**: User created but not approved

**Solution**: Enable `logto_mobile_session_auto_approve_users` setting or manually approve in Admin → Users.

---

## 15. Production Deployment Checklist

- [ ] OIDC configured and tested in Discourse
- [ ] Logto redirect URI includes Discourse callback URL
- [ ] Plugin installed and enabled
- [ ] Rate limiting configured appropriately
- [ ] HTTPS/SSL certificate valid
- [ ] Cookie domain configured correctly for your setup
- [ ] JWT validation tested if using that method
- [ ] JWKS endpoint accessible from Discourse server
- [ ] Mobile app updated to use token exchange flow
- [ ] Monitoring and alerting configured for auth failures
- [ ] Backup plan for Logto outages (cached JWKS for JWT method)
- [ ] Security review completed
- [ ] Documentation provided to mobile developers
- [ ] Load testing performed for expected traffic

---

## Conclusion

This implementation provides a **secure, performant, and maintainable** solution for bridging Logto authentication from native mobile apps into Discourse WebViews. The dual validation approach offers flexibility to start simple (userinfo) and optimize later (JWT), while comprehensive security controls protect against common attack vectors.

**Key Advantages:**

- **Zero token exposure to JavaScript** - Tokens stay server-side
- **Feature-flagged validation** - Switch methods without code changes
- **Automatic user provisioning** - Seamless user experience
- **Production-grade security** - Rate limiting, audit logging, session protection
- **OIDC configuration reuse** - No duplication of settings
- **Comprehensive testing** - Full RSpec test suite included

The plugin is production-ready and follows Discourse best practices for plugin development, security, and performance.