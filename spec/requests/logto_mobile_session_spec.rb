# frozen_string_literal: true

require 'rails_helper'

describe 'LogtoMobile::SessionController', type: :request do

  let(:discovery_url) { "https://auth.example.com/oidc/.well-known/openid-configuration" }
  let(:issuer) { "https://auth.example.com/oidc" }
  let(:userinfo_endpoint) { "https://auth.example.com/oidc/me" }
  let(:jwks_uri) { "https://auth.example.com/oidc/jwks" }

  let(:discovery_document) do
    {
      "issuer" => issuer,
      "userinfo_endpoint" => userinfo_endpoint,
      "jwks_uri" => jwks_uri,
      "token_endpoint" => "https://auth.example.com/oidc/token",
      "id_token_signing_alg_values_supported" => ["ES384"],
    }
  end

  let(:jwks_document) do
    JSON.parse(
      File.read("#{Rails.root}/plugins/discourse-logto-mobile-session/spec/fixtures/jwks.json"),
    )
  end  

  before do
    stub_request(:get, discovery_url).to_return(
      status: 200,
      body: discovery_document.to_json,
      headers: {
        "Content-Type" => "application/json",
      },
    )
  
    stub_request(:get, discovery_document["jwks_uri"]).to_return(
      status: 200,
      body: jwks_document.to_json,
      headers: {
        "Content-Type" => "application/json",
      },
    )

    SiteSetting.openid_connect_enabled = true
    SiteSetting.logto_mobile_session_enabled = true
    SiteSetting.openid_connect_discovery_document = discovery_url
  end

  describe 'POST /api/auth/mobile-session' do
    let(:valid_token) { 'valid_access_token_123' }
    let(:user_info) do
      {
        sub: 'user123',
        email: 'john@example.com',
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

      session_manager = instance_double(LogtoMobile::SessionManager)
      allow(LogtoMobile::SessionManager).to receive(:new).and_return(session_manager)
      allow(session_manager).to receive(:destroy_session)
      allow(session_manager).to receive(:create_session).and_return(
        name: '_forum_session',
        value: 'cookie-value',
        domain: '.example.com',
        path: '/',
        expires_at: 1.hour.from_now.iso8601,
        secure: true,
        http_only: true,
        same_site: 'Lax'
      )
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
        expect(json['user']['email']).to eq('john@example.com')

        # Verify user was created
        user = User.find_by_email('john@example.com')
        expect(user).to be_present
        expect(user.active).to eq(true)
        expect(user.custom_fields['logto_sub']).to eq('user123')
      end
    end

    context 'with valid token and existing user' do
      let!(:existing_user) do
        Fabricate(:user, email: 'john@example.com', username: 'johndoe')
      end

      it 'logs in existing user' do
        expect do
          post '/api/auth/mobile-session', params: {
            access_token: valid_token,
            client_type: 'ios_native'
          }
        end.not_to change { User.count }

        expect(response.status).to eq(201)
        json = JSON.parse(response.body)
        
        expect(json['user']['id']).to eq(existing_user.id)
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
      session_manager = instance_double(LogtoMobile::SessionManager)
      allow(LogtoMobile::SessionManager).to receive(:new).and_return(session_manager)
      allow(session_manager).to receive(:create_session)
      allow(session_manager).to receive(:destroy_session)

      delete '/api/auth/mobile-session'

      expect(response.status).to eq(200)
      json = JSON.parse(response.body)
      expect(json['success']).to eq(true)
      expect(session_manager).to have_received(:destroy_session)
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
