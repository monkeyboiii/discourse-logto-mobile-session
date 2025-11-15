# frozen_string_literal: true

require "rails_helper"

describe LogtoMobile::TokenValidator do
  subject(:validator) { described_class.new }

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
    {
      "keys" => [
        {
          "kty" => "EC",
          "use" => "sig",
          "kid" => "3t2MfAeQScP21BUlT14jco8m-wzL9SkvPZ6UywnYZsY",
          "alg" => "ES384",
          "crv" => "P-384",
        },
      ],
    }
  end

  before do
    SiteSetting.openid_connect_discovery_document = discovery_url
    SiteSetting.logto_mobile_session_require_verified_email = false

    allow(LogtoMobile::OidcMetadata).to receive(:discovery!).and_return(discovery_document)
    allow(LogtoMobile::OidcMetadata).to receive(:algorithms).and_return(["ES384"])
    allow(LogtoMobile::OidcMetadata).to receive(:jwks!).and_return(jwks_document)
  end

  describe "#initialize" do
    it "loads OIDC metadata from discovery document" do
      validator

      expect(LogtoMobile::OidcMetadata).to have_received(:discovery!)
      expect(validator.instance_variable_get(:@issuer)).to eq(issuer)
      expect(validator.instance_variable_get(:@userinfo_endpoint)).to eq(userinfo_endpoint)
      expect(validator.instance_variable_get(:@jwks_uri)).to eq(jwks_uri)
    end

    it "raises error when discovery document is not configured" do
      allow(LogtoMobile::OidcMetadata).to receive(:discovery!).and_raise(
        LogtoMobile::ValidationError,
        "OIDC discovery document not configured",
      )

      expect { described_class.new }.to raise_error(
        LogtoMobile::ValidationError,
        "OIDC discovery document not configured",
      )
    end
  end

  describe "#validate_token" do
    before do
      allow(SiteSetting).to receive(:logto_mobile_session_validation_method).and_return(
        "unsupported",
      )
    end

    it "returns a validation_failed error for unknown strategies" do
      result = validator.validate_token("token")

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("validation_failed")
      expect(result[:message]).to include("Invalid validation method")
    end
  end

  describe "userinfo validation" do
    let(:http_client) { instance_double(Net::HTTP) }
    let(:access_token) { "userinfo-token" }

    before { SiteSetting.logto_mobile_session_validation_method = "userinfo" }

    def stub_userinfo_response(code:, body:)
      response = instance_double(Net::HTTPResponse, code: code, body: body)
      allow(Net::HTTP).to receive(:start).and_yield(http_client)
      allow(http_client).to receive(:request).and_return(response)
    end

    it "uses the userinfo endpoint from discovery document" do
      body = {
        sub: "logto-user",
        email: "user@example.com",
        email_verified: true,
        username: "AppUser",
      }.to_json

      stub_userinfo_response(code: "200", body: body)

      validator.validate_token(access_token)

      expect(Net::HTTP).to have_received(:start).with(
        URI(userinfo_endpoint).hostname,
        URI(userinfo_endpoint).port,
        { use_ssl: true, read_timeout: 10 },
      )
    end

    it "returns normalized user info on success" do
      body = {
        sub: "logto-user",
        email: "USER@Example.com ",
        email_verified: true,
        name: nil,
        username: "AppUser",
        picture: "https://cdn/pic.png",
      }.to_json

      stub_userinfo_response(code: "200", body: body)

      result = validator.validate_token(access_token)

      expect(result).to include(success: true, validation_method: "userinfo")
      expect(result[:user_info]).to include(
        sub: "logto-user",
        email: "user@example.com",
        email_verified: true,
        name: "user",
        username: "AppUser",
        picture: "https://cdn/pic.png",
      )
    end

    it "surfaces invalid_token errors from Logto" do
      stub_userinfo_response(code: "401", body: "{}")

      result = validator.validate_token(access_token)

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("invalid_token")
    end

    it "returns a timeout error when Logto is slow" do
      allow(Net::HTTP).to receive(:start).and_raise(Timeout::Error)

      result = validator.validate_token(access_token)

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("timeout")
    end

    it "enforces verified emails when the setting is enabled" do
      SiteSetting.logto_mobile_session_require_verified_email = true
      body = { sub: "logto-user", email: "user@example.com", email_verified: false }.to_json

      stub_userinfo_response(code: "200", body: body)

      result = validator.validate_token(access_token)

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("request_failed")
      expect(result[:message]).to include("Email not verified")
    end
  end

  describe "jwt validation" do
    let(:exp) { (Time.now + 1.hour).to_i }
    let(:payload) do
      {
        "sub" => "jwt-user",
        "email" => "jwt@example.com",
        "email_verified" => true,
        "preferred_username" => "mobile_user",
        "name" => "Mobile User",
        "picture" => "https://cdn/avatar.png",
        "exp" => exp,
      }
    end

    before { SiteSetting.logto_mobile_session_validation_method = "jwt" }

    it "uses algorithms from OidcMetadata" do
      allow(JWT).to receive(:decode).and_return([payload, {}])

      validator.validate_token("jwt-token")

      expect(LogtoMobile::OidcMetadata).to have_received(:algorithms)
      expect(JWT).to have_received(:decode) do |token, key, verify, options|
        expect(token).to eq("jwt-token")
        expect(key).to be_nil
        expect(verify).to eq(true)
        expect(options[:algorithms]).to eq(["ES384"])
      end
    end

    it "uses issuer from discovery document" do
      allow(JWT).to receive(:decode).and_return([payload, {}])

      validator.validate_token("jwt-token")

      expect(JWT).to have_received(:decode) do |token, key, verify, options|
        expect(token).to eq("jwt-token")
        expect(key).to be_nil
        expect(verify).to eq(true)
        expect(options[:iss]).to eq(issuer)
      end
    end

    it "decodes the JWT and normalizes claims" do
      allow(JWT).to receive(:decode).and_return([payload, {}])

      result = validator.validate_token("jwt-token")

      expect(JWT).to have_received(:decode).once
      expect(result).to include(success: true, validation_method: "jwt")
      expect(result[:user_info]).to include(
        sub: "jwt-user",
        email: "jwt@example.com",
        email_verified: true,
        username: "mobile_user",
        picture: "https://cdn/avatar.png",
      )
      expect(result[:expires_at]).to eq(Time.at(exp))
    end

    it "passes JWKS loader to JWT.decode" do
      allow(JWT).to receive(:decode) do |_token, _key, _verify, options|
        jwks_loader = options[:jwks]
        jwks_result = jwks_loader.call(invalidate: false)

        expect(jwks_result).to have_key(:keys)
        expect(LogtoMobile::OidcMetadata).to have_received(:jwks!).with(force: false)

        [payload, {}]
      end

      validator.validate_token("jwt-token")
    end

    it "forces JWKS refresh when JWT library requests invalidation" do
      allow(JWT).to receive(:decode) do |_token, _key, _verify, options|
        jwks_loader = options[:jwks]
        jwks_loader.call(invalidate: true)

        [payload, {}]
      end

      validator.validate_token("jwt-token")

      expect(LogtoMobile::OidcMetadata).to have_received(:jwks!).with(force: true)
    end

    it "raises error when no algorithms are available" do
      allow(LogtoMobile::OidcMetadata).to receive(:algorithms).and_return([])

      result = validator.validate_token("jwt-token")

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("jwt_validation_failed")
      expect(result[:message]).to include("No signing algorithms available")
    end

    it "returns expired_token when signature is expired" do
      allow(JWT).to receive(:decode).and_raise(JWT::ExpiredSignature)

      result = validator.validate_token("expired-jwt")

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("expired_token")
    end

    it "returns invalid_token when decode fails" do
      allow(JWT).to receive(:decode).and_raise(JWT::DecodeError, "bad signature")

      result = validator.validate_token("bad-jwt")

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("invalid_token")
      expect(result[:message]).to include("bad signature")
    end

    it "returns invalid_issuer when issuer validation fails" do
      allow(JWT).to receive(:decode).and_raise(JWT::InvalidIssuerError)

      result = validator.validate_token("issuer-mismatch")

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("invalid_issuer")
      expect(result[:message]).to include("Token issuer does not match Logto")
    end

    it "returns jwt_validation_failed for unexpected errors" do
      allow(JWT).to receive(:decode).and_raise(StandardError, "boom")

      result = validator.validate_token("broken-jwt")

      expect(result[:success]).to eq(false)
      expect(result[:error]).to eq("jwt_validation_failed")
      expect(result[:message]).to include("boom")
    end
  end

  describe "#normalize_user_info" do
    before { SiteSetting.logto_mobile_session_validation_method = "userinfo" }

    it "downcases email and derives defaults when missing" do
      normalized =
        validator.send(
          :normalize_user_info,
          {
            "sub" => "user-1",
            "email" => "MixedCase.User+test@example.com ",
            "email_verified" => false,
            "name" => nil,
            "username" => nil,
            "preferred_username" => nil,
            "picture" => nil,
          },
        )

      expect(normalized[:email]).to eq("mixedcase.user+test@example.com")
      expect(normalized[:username]).to eq("MixedCase_User_test")
      expect(normalized[:name]).to eq("mixedcase.user+test")
      expect(normalized[:email_verified]).to eq(false)
    end

    it "generates usernames from email when needed" do
      expect(validator.send(:generate_username_from_email, "user.name@example.com")).to eq(
        "user_name",
      )
    end
  end
end
