# frozen_string_literal: true

require "rails_helper"

describe "LogtoMobile::SessionController", type: :request do
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
    SiteSetting.force_hostname = "forum.example.com"
  end

  describe "POST /api/auth/mobile-session" do
    let(:valid_token) { "valid_access_token_123" }
    let(:user_info) do
      {
        sub: "user123",
        email: "john@example.com",
        email_verified: true,
        name: "John Doe",
        username: "johndoe",
      }
    end

    before do
      # Mock token validator
      validator = instance_double(LogtoMobile::TokenValidator)
      allow(LogtoMobile::TokenValidator).to receive(:new).and_return(validator)
      allow(validator).to receive(:validate_token).with(valid_token).and_return(
        { success: true, user_info: user_info, validation_method: "userinfo" },
      )

      session_manager = instance_double(LogtoMobile::SessionManager)
      allow(LogtoMobile::SessionManager).to receive(:new).and_return(session_manager)
      allow(session_manager).to receive(:destroy_session)
      allow(session_manager).to receive(:create_session).and_return(
        auth_token: {
          name: "_t",
          value: {
            token: "auth-token-value",
            user_id: 123,
            username: "johndoe",
            trust_level: 0,
            issued_at: Time.zone.now.to_i,
          },
          domain: "forum.example.com",
          path: "/",
          expires_at: 1.hour.from_now.iso8601,
          secure: false,
          http_only: true,
          same_site: "Lax",
        },
        session_cookie: {
          name: "_forum_session",
          value: "session-value",
          domain: "forum.example.com",
          path: "/",
          expires_at: 1.hour.from_now.iso8601,
          secure: false,
          http_only: true,
          same_site: "Lax",
        },
      )
    end

    context "with valid token and new user" do
      it "creates user and returns both auth_token and session_cookie" do
        post "/api/auth/mobile-session",
             params: {
               access_token: valid_token,
               client_type: "ios_native",
             }

        expect(response.status).to eq(201)
        json = JSON.parse(response.body)

        expect(json["success"]).to eq(true)

        # Verify auth_token (_t cookie)
        expect(json["auth_token"]).to be_present
        expect(json["auth_token"]["name"]).to eq("_t")
        expect(json["auth_token"]["value"]).to be_present
        expect(json["auth_token"]["value"]).to be_a(Hash)
        expect(json["auth_token"]["value"]["token"]).to be_present
        expect(json["auth_token"]["http_only"]).to eq(true)

        # Verify session_cookie
        expect(json["session_cookie"]).to be_present
        expect(json["session_cookie"]["name"]).to eq("_forum_session")
        expect(json["session_cookie"]["http_only"]).to eq(true)

        expect(json["user"]["username"]).to eq("johndoe")
        expect(json["user"]["email"]).to eq("john@example.com")

        # Verify user was created
        user = User.find_by_email("john@example.com")
        expect(user).to be_present
        expect(user.active).to eq(true)
        expect(user.custom_fields["logto_sub"]).to eq("user123")
      end
    end

    context "with valid token and existing user" do
      let!(:existing_user) { Fabricate(:user, email: "john@example.com", username: "johndoe") }

      it "logs in existing user" do
        expect do
          post "/api/auth/mobile-session",
               params: {
                 access_token: valid_token,
                 client_type: "ios_native",
               }
        end.not_to change { User.count }

        expect(response.status).to eq(201)
        json = JSON.parse(response.body)

        expect(json["user"]["id"]).to eq(existing_user.id)
      end
    end

    context "with invalid token" do
      before do
        validator = instance_double(LogtoMobile::TokenValidator)
        allow(LogtoMobile::TokenValidator).to receive(:new).and_return(validator)
        allow(validator).to receive(:validate_token).and_return(
          { success: false, error: "invalid_token", message: "Token is invalid" },
        )
      end

      it "returns 401 unauthorized" do
        post "/api/auth/mobile-session",
             params: {
               access_token: "invalid_token",
               client_type: "ios_native",
             }

        expect(response.status).to eq(401)
        json = JSON.parse(response.body)
        expect(json["error"]).to eq("invalid_token")
      end
    end

    context "without access_token parameter" do
      it "returns 401 with validation error" do
        post "/api/auth/mobile-session", params: { client_type: "ios_native" }

        expect(response.status).to eq(401)
        json = JSON.parse(response.body)
        expect(json["error"]).to eq("validation_error")
      end
    end

    context "without client_type parameter" do
      it "returns 400 bad request" do
        post "/api/auth/mobile-session", params: { access_token: valid_token }

        expect(response.status).to eq(400)
        json = JSON.parse(response.body)
        expect(json["error"]).to eq("client_type required")
      end
    end

    context "with disallowed client_type" do
      it "returns 403 forbidden" do
        post "/api/auth/mobile-session",
             params: {
               access_token: valid_token,
               client_type: "web_browser",
             }

        expect(response.status).to eq(403)
        json = JSON.parse(response.body)
        expect(json["error"]).to eq("invalid_client_type")
      end
    end

    context "with rate limiting" do
      it "blocks after exceeding limit" do
        SiteSetting.logto_mobile_session_rate_limit_per_minute = 2

        # First two requests should succeed
        2.times do
          post "/api/auth/mobile-session",
               params: {
                 access_token: valid_token,
                 client_type: "ios_native",
               }
          expect(response.status).to eq(201)
        end

        # Third request should be rate limited
        post "/api/auth/mobile-session",
             params: {
               access_token: valid_token,
               client_type: "ios_native",
             }

        expect(response.status).to eq(429)
        json = JSON.parse(response.body)
        expect(json["error"]).to eq("rate_limit_exceeded")
      end
    end

    context "with cookie configuration" do
      before do
        # Don't mock SessionManager for these tests - use real implementation
        allow(LogtoMobile::SessionManager).to receive(:new).and_call_original
      end

      it "uses full domain not apex domain with dot prefix" do
        post "/api/auth/mobile-session",
             params: { access_token: valid_token, client_type: "ios_native" }.to_json,
             headers: {
               "CONTENT_TYPE" => "application/json",
               "HTTP_HOST" => "forum.example.com",
             }

        expect(response.status).to eq(201)
        json = JSON.parse(response.body)

        # Should be 'forum.example.com', not '.example.com'
        expect(json["auth_token"]["domain"]).to eq("forum.example.com")
        expect(json["auth_token"]["domain"]).not_to start_with(".")
        expect(json["session_cookie"]["domain"]).to eq("forum.example.com")
      end

      it "respects Discourse persistent_sessions setting" do
        SiteSetting.persistent_sessions = false

        post "/api/auth/mobile-session",
             params: { access_token: valid_token, client_type: "ios_native" }.to_json,
             headers: {
               "CONTENT_TYPE" => "application/json",
             }

        expect(response.status).to eq(201)
        json = JSON.parse(response.body)

        # When persistent_sessions is false, expires_at should be nil
        expect(json["auth_token"]["expires_at"]).to be_nil
        expect(json["session_cookie"]["expires_at"]).to be_nil
      end

      it "uses maximum_session_age when persistent_sessions enabled" do
        SiteSetting.persistent_sessions = true
        SiteSetting.maximum_session_age = 24

        post "/api/auth/mobile-session",
             params: { access_token: valid_token, client_type: "ios_native" }.to_json,
             headers: {
               "CONTENT_TYPE" => "application/json",
             }

        expect(response.status).to eq(201)
        json = JSON.parse(response.body)

        # Should have expiration set
        expect(json["auth_token"]["expires_at"]).not_to be_nil
        expires_time = Time.parse(json["auth_token"]["expires_at"])
        expect(expires_time).to be > Time.now
        expect(expires_time).to be <= (Time.now + 25.hours)
      end
    end
  end

  describe "DELETE /api/auth/mobile-session" do
    it "destroys the session" do
      session_manager = instance_double(LogtoMobile::SessionManager)
      allow(LogtoMobile::SessionManager).to receive(:new).and_return(session_manager)
      allow(session_manager).to receive(:create_session)
      allow(session_manager).to receive(:destroy_session)

      delete "/api/auth/mobile-session"

      expect(response.status).to eq(200)
      json = JSON.parse(response.body)
      expect(json["success"]).to eq(true)
      expect(session_manager).to have_received(:destroy_session)
    end
  end

  describe "GET /api/auth/mobile-session/health" do
    it "returns health status" do
      get "/api/auth/mobile-session/health"

      expect(response.status).to eq(200)
      json = JSON.parse(response.body)

      expect(json["healthy"]).to be_in([true, false])
      expect(json["checks"]).to be_present
      expect(json["version"]).to eq(LogtoMobile::VERSION)
    end
  end
end
