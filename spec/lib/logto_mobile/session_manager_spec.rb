# frozen_string_literal: true

require "rails_helper"

describe LogtoMobile::SessionManager do
  subject(:manager) { described_class.new(controller) }

  let(:controller) { instance_double("LogtoMobile::SessionController", request: request) }
  let(:cookie_jar) { instance_double("ActionDispatch::Cookies::CookieJar") }
  let(:encrypted_cookies) { { "_t" => auth_token_data, "_forum_session" => "session-value" } }
  let(:auth_token_data) do
    {
      token: "test-auth-token-value",
      user_id: user.id,
      username: user.username,
      trust_level: user.trust_level,
      issued_at: Time.zone.now.to_i,
    }
  end
  let(:request) do
    instance_double(ActionDispatch::Request, host: "forum.example.com", cookie_jar: cookie_jar)
  end
  let(:user) { Fabricate(:user) }

  before do
    allow(controller).to receive(:log_on_user)
    allow(controller).to receive(:log_off_user)
    allow(cookie_jar).to receive(:encrypted).and_return(encrypted_cookies)
  end

  describe "#create_session" do
    it "creates a Discourse session and returns both auth_token and session_cookie" do
      allow(SiteSetting).to receive(:force_hostname).and_return("forum.example.com")
      allow(SiteSetting).to receive(:persistent_sessions).and_return(true)
      allow(SiteSetting).to receive(:maximum_session_age).and_return(24)
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("production"))
      fixed_time = Time.utc(2024, 1, 1, 12, 0, 0)
      allow(Time).to receive(:now).and_return(fixed_time)

      result = manager.create_session(user)

      expect(controller).to have_received(:log_on_user).with(user)

      # Verify auth_token cookie
      expect(result[:auth_token][:name]).to eq("_t")
      expect(result[:auth_token][:value]).to eq(auth_token_data)
      expect(result[:auth_token][:domain]).to eq("forum.example.com")
      expect(result[:auth_token][:expires_at]).to eq((fixed_time + 24.hours).iso8601)
      expect(result[:auth_token][:path]).to eq("/")
      expect(result[:auth_token][:secure]).to eq(true)
      expect(result[:auth_token][:http_only]).to eq(true)
      expect(result[:auth_token][:same_site]).to eq("Lax")

      # Verify session_cookie
      expect(result[:session_cookie][:name]).to eq("_forum_session")
      expect(result[:session_cookie][:value]).to eq("session-value")
      expect(result[:session_cookie][:domain]).to eq("forum.example.com")
      expect(result[:session_cookie][:expires_at]).to eq((fixed_time + 24.hours).iso8601)
      expect(result[:session_cookie][:path]).to eq("/")
      expect(result[:session_cookie][:secure]).to eq(true)
      expect(result[:session_cookie][:http_only]).to eq(true)
      expect(result[:session_cookie][:same_site]).to eq("Lax")
    end
  end

  describe "#destroy_session" do
    it "logs the user out through the controller" do
      manager.destroy_session

      expect(controller).to have_received(:log_off_user)
    end
  end

  describe "#extract_cookie_domain" do
    it "prefers the configured force_hostname setting when present" do
      allow(SiteSetting).to receive(:force_hostname).and_return("custom-domain.com")

      domain = manager.send(:extract_cookie_domain)

      expect(domain).to eq("custom-domain.com")
    end

    it "returns the full domain from request host" do
      allow(SiteSetting).to receive(:force_hostname).and_return("")
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("production"))
      allow(request).to receive(:host).and_return("forum.example.com")

      domain = manager.send(:extract_cookie_domain)

      expect(domain).to eq("forum.example.com")
    end

    it "returns localhost for localhost environments" do
      allow(SiteSetting).to receive(:force_hostname).and_return("")
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new("test"))
      allow(request).to receive(:host).and_return("localhost")

      domain = manager.send(:extract_cookie_domain)

      expect(domain).to eq("localhost")
    end
  end
end
