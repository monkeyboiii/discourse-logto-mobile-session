# frozen_string_literal: true

module LogtoMobile
  # Validates Logto OIDC access tokens via userinfo endpoint or JWT signature
  # Uses centralized OIDC metadata from OidcMetadata service
  class TokenValidator
    require "net/http"
    require "uri"
    require "json"
    require "jwt"

    # Initialize validator and load OIDC metadata from discovery document
    # @raise [ValidationError] If discovery document is not configured or invalid
    def initialize
      @validation_method = SiteSetting.logto_mobile_session_validation_method

      # Load OIDC metadata from discovery document
      discovery = OidcMetadata.discovery!
      @issuer = discovery["issuer"]
      @userinfo_endpoint = discovery["userinfo_endpoint"]
      @jwks_uri = discovery["jwks_uri"]
    end

    # Main validation entry point
    # @param access_token [String] The access token to validate
    # @return [Hash] Validation result with :success, :error, :message, and optional :user_info
    def validate_token(access_token)
      case @validation_method
      when "userinfo"
        validate_via_userinfo(access_token)
      when "jwt"
        validate_via_jwt(access_token)
      else
        raise ValidationError, "Invalid validation method: #{@validation_method}"
      end
    rescue StandardError => e
      Rails.logger.error("[LogtoMobileSession] Token validation failed: #{e.message}")
      { success: false, error: "validation_failed", message: e.message }
    end

    private

    # METHOD 1: Validate via Logto's /userinfo endpoint
    # Uses the exact endpoint from the discovery document
    # @param access_token [String] The access token to validate
    # @return [Hash] Validation result
    def validate_via_userinfo(access_token)
      uri = URI(@userinfo_endpoint)

      request = Net::HTTP::Get.new(uri)
      request["Authorization"] = "Bearer #{access_token}"

      response =
        Net::HTTP.start(
          uri.hostname,
          uri.port,
          use_ssl: uri.scheme == "https",
          read_timeout: 10,
        ) { |http| http.request(request) }

      case response.code.to_i
      when 200
        user_info = JSON.parse(response.body)
        validate_user_claims(user_info)
        { success: true, user_info: normalize_user_info(user_info), validation_method: "userinfo" }
      when 401
        { success: false, error: "invalid_token", message: "Token is invalid or expired" }
      when 403
        { success: false, error: "insufficient_scope", message: "Token lacks required permissions" }
      else
        { success: false, error: "validation_failed", message: "HTTP #{response.code}" }
      end
    rescue Timeout::Error
      { success: false, error: "timeout", message: "Logto userinfo endpoint timeout" }
    rescue StandardError => e
      { success: false, error: "request_failed", message: e.message }
    end

    # METHOD 2: Validate via JWT signature using Logto's public keys
    # Uses JWKS and algorithms from OidcMetadata service
    # @param access_token [String] The access token to validate
    # @return [Hash] Validation result
    def validate_via_jwt(access_token)
      # Get supported algorithms from metadata
      algorithms = OidcMetadata.algorithms
      raise ValidationError, "No signing algorithms available" if algorithms.empty?

      # Create JWKS loader with caching and automatic refresh
      jwk_loader =
        lambda do |options|
          jwks_data = OidcMetadata.jwks!(force: options[:invalidate])
          jwks_data.deep_symbolize_keys
        end

      # Decode and verify JWT
      decoded_token =
        JWT.decode(
          access_token,
          nil,
          true, # Verify signature
          {
            algorithms: algorithms,
            iss: @issuer,
            verify_iss: true,
            verify_aud: false, # May vary based on Logto config
            verify_exp: true,
            verify_iat: true,
            jwks: jwk_loader,
          },
        )

      payload = decoded_token[0]

      # Convert JWT claims to userinfo format
      user_info = {
        "sub" => payload["sub"],
        "email" => payload["email"],
        "email_verified" => payload["email_verified"],
        "name" => payload["name"],
        "username" => payload["username"] || payload["preferred_username"],
        "picture" => payload["picture"],
      }

      validate_user_claims(user_info)

      {
        success: true,
        user_info: normalize_user_info(user_info),
        validation_method: "jwt",
        expires_at: Time.at(payload["exp"]),
      }
    rescue JWT::ExpiredSignature
      { success: false, error: "expired_token", message: "Token has expired" }
    rescue JWT::InvalidIssuerError
      { success: false, error: "invalid_issuer", message: "Token issuer does not match Logto" }
    rescue JWT::DecodeError, JWT::VerificationError => e
      { success: false, error: "invalid_token", message: "JWT validation failed: #{e.message}" }
    rescue StandardError => e
      { success: false, error: "jwt_validation_failed", message: e.message }
    end

    # Validate required claims are present
    # @param user_info [Hash] User info claims
    # @raise [ValidationError] If required claims are missing or invalid
    def validate_user_claims(user_info)
      raise ValidationError, "Missing 'sub' claim" if user_info["sub"].blank?
      raise ValidationError, "Missing 'email' claim" if user_info["email"].blank?

      if SiteSetting.logto_mobile_session_require_verified_email
        unless user_info["email_verified"] == true
          raise ValidationError, "Email not verified in Logto"
        end
      end
    end

    # Normalize user info to consistent format
    # @param user_info [Hash] Raw user info from token or userinfo endpoint
    # @return [Hash] Normalized user info with symbolized keys
    def normalize_user_info(user_info)
      raw_email = user_info["email"]&.strip
      normalized_email = raw_email&.downcase
      derived_username = user_info["username"] || user_info["preferred_username"]

      {
        sub: user_info["sub"],
        email: normalized_email,
        email_verified: user_info["email_verified"] == true,
        name: user_info["name"] || normalized_email&.split("@")&.first,
        username: derived_username || generate_username_from_email(raw_email),
        picture: user_info["picture"],
      }
    end

    # Generate username from email address
    # @param email [String] Email address
    # @return [String, nil] Generated username
    def generate_username_from_email(email)
      return nil if email.blank?
      email.split("@").first.gsub(/[^a-z0-9_-]/i, "_").slice(0, 20)
    end
  end
end
