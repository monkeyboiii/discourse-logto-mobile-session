# frozen_string_literal: true

require 'rails_helper'

describe LogtoMobile::TokenValidator do
  subject(:validator) { described_class.new }

  let(:discovery_url) do
    'https://tenant.logto.app/oidc/.well-known/openid-configuration'
  end

  before do
    SiteSetting.openid_connect_discovery_document = discovery_url
    SiteSetting.logto_mobile_session_require_verified_email = false
  end

  describe '#validate_token' do
    before do
      allow(SiteSetting).to receive(:logto_mobile_session_validation_method).and_return('unsupported')
    end

    it 'returns a validation_failed error for unknown strategies' do
      result = validator.validate_token('token')

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq('validation_failed')
      expect(result[:message]).to include('Invalid validation method')
    end
  end

  describe 'userinfo validation' do
    let(:http_client) { instance_double(Net::HTTP) }
    let(:access_token) { 'userinfo-token' }

    before do
      SiteSetting.logto_mobile_session_validation_method = 'userinfo'
    end

    def stub_userinfo_response(code:, body:)
      response = instance_double(Net::HTTPResponse, code: code, body: body)
      allow(Net::HTTP).to receive(:start).and_yield(http_client)
      allow(http_client).to receive(:request).and_return(response)
    end

    it 'returns normalized user info on success' do
      body = {
        sub: 'logto-user',
        email: 'USER@Example.com ',
        email_verified: true,
        name: nil,
        username: 'AppUser',
        picture: 'https://cdn/pic.png'
      }.to_json

      stub_userinfo_response(code: '200', body: body)

      result = validator.validate_token(access_token)

      expect(result).to include(success: true, validation_method: 'userinfo')
      expect(result[:user_info]).to include(
        sub: 'logto-user',
        email: 'user@example.com',
        email_verified: true,
        name: 'user',
        username: 'AppUser',
        picture: 'https://cdn/pic.png'
      )
    end

    it 'surfaces invalid_token errors from Logto' do
      stub_userinfo_response(code: '401', body: '{}')

      result = validator.validate_token(access_token)

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq('invalid_token')
    end

    it 'returns a timeout error when Logto is slow' do
      allow(Net::HTTP).to receive(:start).and_raise(Timeout::Error)

      result = validator.validate_token(access_token)

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq('timeout')
    end

    it 'enforces verified emails when the setting is enabled' do
      SiteSetting.logto_mobile_session_require_verified_email = true
      body = {
        sub: 'logto-user',
        email: 'user@example.com',
        email_verified: false
      }.to_json

      stub_userinfo_response(code: '200', body: body)

      result = validator.validate_token(access_token)

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq('request_failed')
      expect(result[:message]).to include('Email not verified')
    end
  end

  describe 'jwt validation' do
    let(:exp) { (Time.now + 1.hour).to_i }
    let(:payload) do
      {
        'sub' => 'jwt-user',
        'email' => 'jwt@example.com',
        'email_verified' => true,
        'preferred_username' => 'mobile_user',
        'name' => 'Mobile User',
        'picture' => 'https://cdn/avatar.png',
        'exp' => exp
      }
    end

    before do
      SiteSetting.logto_mobile_session_validation_method = 'jwt'
    end

    it 'decodes the JWT and normalizes claims' do
      allow(JWT).to receive(:decode).and_return([payload, {}])

      result = validator.validate_token('jwt-token')

      expect(JWT).to have_received(:decode).once
      expect(result).to include(success: true, validation_method: 'jwt')
      expect(result[:user_info]).to include(
        sub: 'jwt-user',
        email: 'jwt@example.com',
        email_verified: true,
        username: 'mobile_user',
        picture: 'https://cdn/avatar.png'
      )
      expect(result[:expires_at]).to eq(Time.at(exp))
    end

    it 'returns expired_token when signature is expired' do
      allow(JWT).to receive(:decode).and_raise(JWT::ExpiredSignature)

      result = validator.validate_token('expired-jwt')

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq('expired_token')
    end

    it 'returns invalid_token when decode fails' do
      allow(JWT).to receive(:decode).and_raise(JWT::DecodeError, 'bad signature')

      result = validator.validate_token('bad-jwt')

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq('invalid_token')
      expect(result[:message]).to include('bad signature')
    end
  end

  describe '#fetch_jwks' do
    before do
      SiteSetting.logto_mobile_session_validation_method = 'jwt'
    end

    def build_http_response(klass:, code:, body:)
      response = klass.new('1.1', code, 'OK')
      response.instance_variable_set(:@read, true)
      response.instance_variable_set(:@body, body)
      response
    end

    it 'caches JWKS responses until the TTL expires' do
      jwks_body = { keys: [{ kid: 'kid-1' }] }.to_json
      http_response = build_http_response(klass: Net::HTTPOK, code: '200', body: jwks_body)

      allow(Net::HTTP).to receive(:get_response).and_return(http_response)

      first = validator.send(:fetch_jwks)
      second = validator.send(:fetch_jwks)

      expect(first).to eq(second)
      expect(Net::HTTP).to have_received(:get_response).once
    end

    it 'refreshes the JWKS when the cache expires' do
      first_body = { keys: [{ kid: 'kid-1' }] }.to_json
      second_body = { keys: [{ kid: 'kid-2' }] }.to_json
      first_response = build_http_response(klass: Net::HTTPOK, code: '200', body: first_body)
      second_response = build_http_response(klass: Net::HTTPOK, code: '200', body: second_body)

      allow(Net::HTTP).to receive(:get_response).and_return(first_response, second_response)

      validator.send(:fetch_jwks)
      validator.instance_variable_set(
        :@jwks_cached_at,
        Time.now - (described_class::JWKS_CACHE_TTL + 5)
      )

      validator.send(:fetch_jwks)

      expect(Net::HTTP).to have_received(:get_response).twice
      expect(validator.instance_variable_get(:@jwks_cache)).to eq(JSON.parse(second_body))
    end

    it 'forces a refresh when requested' do
      first_response = build_http_response(
        klass: Net::HTTPOK,
        code: '200',
        body: { keys: [{ kid: 'kid-1' }] }.to_json
      )
      second_response = build_http_response(
        klass: Net::HTTPOK,
        code: '200',
        body: { keys: [{ kid: 'kid-2' }] }.to_json
      )

      allow(Net::HTTP).to receive(:get_response).and_return(first_response, second_response)

      validator.send(:fetch_jwks)
      validator.send(:fetch_jwks, force_refresh: true)

      expect(Net::HTTP).to have_received(:get_response).twice
    end

    it 'raises a validation error when Logto does not return success' do
      error_response = build_http_response(
        klass: Net::HTTPInternalServerError,
        code: '500',
        body: 'oops'
      )
      allow(Net::HTTP).to receive(:get_response).and_return(error_response)

      expect { validator.send(:fetch_jwks) }.to raise_error(LogtoMobile::ValidationError)
    end
  end

  describe '#normalize_user_info' do
    before { SiteSetting.logto_mobile_session_validation_method = 'userinfo' }

    it 'downcases email and derives defaults when missing' do
      normalized = validator.send(
        :normalize_user_info,
        {
          'sub' => 'user-1',
          'email' => 'MixedCase.User+test@example.com ',
          'email_verified' => false,
          'name' => nil,
          'username' => nil,
          'preferred_username' => nil,
          'picture' => nil
        }
      )

      expect(normalized[:email]).to eq('mixedcase.user+test@example.com')
      expect(normalized[:username]).to eq('MixedCase_User_test')
      expect(normalized[:name]).to eq('mixedcase.user+test')
      expect(normalized[:email_verified]).to eq(false)
    end

    it 'generates usernames from email when needed' do
      expect(validator.send(:generate_username_from_email, 'user.name@example.com')).to eq('user_name')
    end
  end

  describe 'Hash#deep_symbolize_keys extension' do
    it 'recursively symbolises nested structures' do
      payload = {
        'parent' => {
          'child' => [
            { 'k' => 'v' },
            { 'nested' => { 'key' => 'value' } }
          ]
        }
      }

      expect(payload.deep_symbolize_keys).to eq(
        parent: {
          child: [
            { k: 'v' },
            { nested: { key: 'value' } }
          ]
        }
      )
    end
  end
end
