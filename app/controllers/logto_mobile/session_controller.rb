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
        rate_limiting: defined?(RackAttack) ? true : 'not_enabled'
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
      return handle_validation_error(exception) if exception.is_a?(LogtoMobile::ValidationError)
      return handle_provisioning_error(exception) if exception.is_a?(LogtoMobile::ProvisioningError)

      Rails.logger.error("[LogtoMobileSession] Unexpected error: #{exception.message}\n#{exception.backtrace.join("\n")}")
      raise exception if Rails.env.test?
      render json: {
        error: 'internal_error',
        message: 'An unexpected error occurred'
      }, status: :internal_server_error
    end
  end
end
