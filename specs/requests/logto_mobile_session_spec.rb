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