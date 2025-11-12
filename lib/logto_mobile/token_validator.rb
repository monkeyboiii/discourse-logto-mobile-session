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
    rescue JWT::ExpiredSignature
      { success: false, error: 'expired_token', message: 'Token has expired' }
    rescue JWT::DecodeError, JWT::VerificationError => e
      { success: false, error: 'invalid_token', message: "JWT validation failed: #{e.message}" }
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
      raw_email = user_info['email']&.strip
      normalized_email = raw_email&.downcase
      derived_username = user_info['username'] || user_info['preferred_username']

      {
        sub: user_info['sub'],
        email: normalized_email,
        email_verified: user_info['email_verified'] == true,
        name: user_info['name'] || normalized_email&.split('@')&.first,
        username: derived_username || generate_username_from_email(raw_email),
        picture: user_info['picture']
      }
    end

    def generate_username_from_email(email)
      return nil if email.blank?
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
