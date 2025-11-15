# frozen_string_literal: true

require "rails_helper"

RSpec.describe LogtoMobile::OidcMetadata do
  let(:discovery_url) { "https://auth.example.com/oidc/.well-known/openid-configuration" }
  let(:jwks_url) { "https://auth.example.com/oidc/jwks" }

  let(:discovery_document) do
    JSON.parse(
      File.read(
        "#{Rails.root}/plugins/discourse-logto-mobile-session/spec/fixtures/openid-configuration.json",
      ),
    )
  end

  let(:jwks_document) do
    JSON.parse(
      File.read("#{Rails.root}/plugins/discourse-logto-mobile-session/spec/fixtures/jwks.json"),
    )
  end

  before do
    Discourse.cache.clear

    # Stub BEFORE setting site settings so refresh_all! (triggered by setting changes) has data
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

    # Now safe to set site settings (these trigger :site_setting_changed event)
    SiteSetting.openid_connect_discovery_document = discovery_url
    SiteSetting.logto_mobile_session_enabled = true
  end

  after { Discourse.cache.clear }

  describe "#fetch_discovery" do
    it "fetches and caches discovery document" do
      result = described_class.fetch_discovery
      expect(result).to be_a(Hash)
      expect(result["issuer"]).to eq(discovery_document["issuer"])
      expect(result["jwks_uri"]).to eq(discovery_document["jwks_uri"])

      WebMock.reset!

      cached_result = described_class.fetch_discovery
      expect(cached_result).to eq(result)
    end

    it "returns nil when discovery URL is blank" do
      SiteSetting.openid_connect_discovery_document = ""
      expect(described_class.fetch_discovery).to be_nil
    end

    it "caches discovery document for configured TTL" do
      described_class.fetch_discovery
      expect(Discourse.cache.exist?(described_class::DISCOVERY_CACHE_KEY)).to be true

      Discourse.cache.delete(described_class::DISCOVERY_CACHE_KEY)
      expect(Discourse.cache.exist?(described_class::DISCOVERY_CACHE_KEY)).to be false
    end
  end

  describe "#discovery!" do
    it "raises error when discovery document is not configured" do
      SiteSetting.openid_connect_discovery_document = ""
      expect { described_class.discovery! }.to raise_error(
        LogtoMobile::ValidationError,
        "OIDC discovery document not configured",
      )
    end

    it "raises error when discovery document is missing required fields" do
      Discourse.cache.clear
      incomplete_doc = { "issuer" => "https://example.com" }
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: incomplete_doc.to_json,
        headers: {
          "Content-Type" => "application/json",
        },
      )

      expect { described_class.discovery! }.to raise_error(
        LogtoMobile::ValidationError,
        /missing required fields/,
      )
    end

    it "returns discovery document when valid" do
      result = described_class.discovery!
      expect(result["issuer"]).to eq(discovery_document["issuer"])
    end
  end

  describe "discovery document field accessors" do
    before {}

    it "returns issuer" do
      expect(described_class.issuer).to eq(discovery_document["issuer"])
    end

    it "returns userinfo_endpoint" do
      expect(described_class.userinfo_endpoint).to eq(discovery_document["userinfo_endpoint"])
    end

    it "returns jwks_uri" do
      expect(described_class.jwks_uri).to eq(discovery_document["jwks_uri"])
    end

    it "returns token_endpoint" do
      expect(described_class.token_endpoint).to eq(discovery_document["token_endpoint"])
    end

    it "returns end_session_endpoint" do
      expect(described_class.end_session_endpoint).to eq(discovery_document["end_session_endpoint"])
    end

    it "returns id_token_signing_alg_values_supported" do
      expect(described_class.id_token_signing_alg_values_supported).to eq(
        discovery_document["id_token_signing_alg_values_supported"],
      )
    end
  end

  describe "#fetch_jwks" do
    before {}

    it "fetches and caches JWKS" do
      result = described_class.fetch_jwks
      expect(result).to be_a(Hash)
      expect(result["keys"]).to be_an(Array)
      expect(result["keys"].first["kty"]).to eq("EC")

      WebMock.reset!

      cached_result = described_class.fetch_jwks
      expect(cached_result).to eq(result)
    end

    it "forces refresh when force parameter is true" do
      described_class.fetch_jwks
      Discourse.cache.write(described_class::JWKS_CACHE_KEY, { "keys" => [] })

      result = described_class.fetch_jwks(force: true)
      expect(result["keys"].first["kty"]).to eq("EC")
    end

    it "returns nil when jwks_uri is blank" do
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: { "issuer" => "https://example.com" }.to_json,
        headers: {
          "Content-Type" => "application/json",
        },
      )

      Discourse.cache.clear
      expect(described_class.fetch_jwks).to be_nil
    end
  end

  describe "#jwks!" do
    before {}

    it "returns JWKS when available" do
      result = described_class.jwks!
      expect(result["keys"]).to be_an(Array)
    end

    it "raises error when JWKS is not available" do
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: {
          "issuer" => "https://example.com",
          "userinfo_endpoint" => "https://example.com/me",
          "jwks_uri" => "",
        }.to_json,
      )

      Discourse.cache.clear
      expect { described_class.jwks! }.to raise_error(
        LogtoMobile::ValidationError,
        "JWKS not available",
      )
    end
  end

  describe "#algorithms" do
    before {}

    it "derives algorithms from JWKS keys" do
      expect(described_class.algorithms).to eq(["ES384"])
    end

    it "falls back to discovery document when JWKS has no alg values" do
      jwks_without_alg = { "keys" => [{ "kty" => "EC", "use" => "sig" }] }
      stub_request(:get, discovery_document["jwks_uri"]).to_return(
        status: 200,
        body: jwks_without_alg.to_json,
        headers: {
          "Content-Type" => "application/json",
        },
      )

      expect(described_class.algorithms).to eq(
        discovery_document["id_token_signing_alg_values_supported"],
      )
    end

    it "defaults to RS256 when no algorithms are specified" do
      minimal_discovery = {
        "issuer" => "https://example.com",
        "jwks_uri" => discovery_document["jwks_uri"],
        "userinfo_endpoint" => "https://example.com/me",
      }
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: minimal_discovery.to_json,
        headers: {
          "Content-Type" => "application/json",
        },
      )

      jwks_without_alg = { "keys" => [{ "kty" => "RSA", "use" => "sig" }] }
      stub_request(:get, discovery_document["jwks_uri"]).to_return(
        status: 200,
        body: jwks_without_alg.to_json,
        headers: {
          "Content-Type" => "application/json",
        },
      )

      Discourse.cache.clear
      expect(described_class.algorithms).to eq(["RS256"])
    end
  end

  describe "#refresh_all!" do
    it "invalidates all caches" do
      described_class.fetch_discovery
      described_class.fetch_jwks

      expect(Discourse.cache.exist?(described_class::DISCOVERY_CACHE_KEY)).to be true
      expect(Discourse.cache.exist?(described_class::JWKS_CACHE_KEY)).to be true

      # Disable plugin so refresh_all! doesn't warm the cache
      SiteSetting.logto_mobile_session_enabled = false
      described_class.refresh_all!

      expect(Discourse.cache.exist?(described_class::DISCOVERY_CACHE_KEY)).to be false
      expect(Discourse.cache.exist?(described_class::JWKS_CACHE_KEY)).to be false
    end

    it "warms cache when plugin is enabled" do
      SiteSetting.logto_mobile_session_enabled = true

      described_class.refresh_all!

      expect(Discourse.cache.exist?(described_class::DISCOVERY_CACHE_KEY)).to be true
      expect(Discourse.cache.exist?(described_class::JWKS_CACHE_KEY)).to be true
    end

    it "does not warm cache when plugin is disabled" do
      SiteSetting.logto_mobile_session_enabled = false

      described_class.refresh_all!

      expect(Discourse.cache.exist?(described_class::DISCOVERY_CACHE_KEY)).to be false
      expect(Discourse.cache.exist?(described_class::JWKS_CACHE_KEY)).to be false
    end

    it "handles cache warming errors gracefully" do
      SiteSetting.openid_connect_discovery_document = ""
      SiteSetting.logto_mobile_session_enabled = true

      expect { described_class.refresh_all! }.not_to raise_error
    end
  end

  describe "HTTP error handling" do
    it "raises ValidationError on HTTP error" do
      Discourse.cache.clear
      stub_request(:get, discovery_url).to_return(status: 500, body: "Internal Server Error")

      expect { described_class.discovery! }.to raise_error(LogtoMobile::ValidationError, /HTTP 500/)
    end

    it "raises ValidationError on network error" do
      Discourse.cache.clear
      stub_request(:get, discovery_url).to_raise(Faraday::ConnectionFailed.new("Connection failed"))

      expect { described_class.discovery! }.to raise_error(
        LogtoMobile::ValidationError,
        /Network error/,
      )
    end

    it "raises ValidationError on invalid JSON" do
      Discourse.cache.clear
      stub_request(:get, discovery_url).to_return(
        status: 200,
        body: "not json",
        headers: {
          "Content-Type" => "application/json",
        },
      )

      expect { described_class.discovery! }.to raise_error(
        LogtoMobile::ValidationError,
        /Invalid JSON/,
      )
    end
  end
end
