# frozen_string_literal: true

module LogtoMobile
  # Service for fetching and caching OIDC discovery metadata and JWKS
  # Centralizes all HTTP calls to the identity provider and provides
  # cache invalidation when plugin settings change.
  module OidcMetadata
    extend self

    DISCOVERY_CACHE_TTL = 10.minutes
    JWKS_CACHE_TTL = 1.hour

    DISCOVERY_CACHE_KEY = "logto_mobile:oidc_discovery"
    JWKS_CACHE_KEY = "logto_mobile:jwks"

    # Fetch discovery document with caching
    # @return [Hash, nil] Parsed discovery document or nil if not configured
    def fetch_discovery
      discovery_url = SiteSetting.openid_connect_discovery_document
      return nil if discovery_url.blank?

      Discourse
        .cache
        .fetch(DISCOVERY_CACHE_KEY, expires_in: DISCOVERY_CACHE_TTL) do
          Rails.logger.info(
            "[LogtoMobileSession] Fetching discovery document from #{discovery_url}",
          )
          fetch_json(discovery_url)
        end
    end

    # Fetch discovery document and raise error if missing or invalid
    # @return [Hash] Parsed discovery document
    # @raise [ValidationError] If discovery document is not configured or invalid
    def discovery!
      doc = fetch_discovery
      raise ValidationError, "OIDC discovery document not configured" if doc.nil?

      validate_discovery_document!(doc)
      doc
    end

    # Get issuer from discovery document
    # @return [String, nil]
    def issuer
      fetch_discovery&.dig("issuer")
    end

    # Get userinfo endpoint from discovery document
    # @return [String, nil]
    def userinfo_endpoint
      fetch_discovery&.dig("userinfo_endpoint")
    end

    # Get JWKS URI from discovery document
    # @return [String, nil]
    def jwks_uri
      fetch_discovery&.dig("jwks_uri")
    end

    # Get token endpoint from discovery document
    # @return [String, nil]
    def token_endpoint
      fetch_discovery&.dig("token_endpoint")
    end

    # Get end session endpoint from discovery document
    # @return [String, nil]
    def end_session_endpoint
      fetch_discovery&.dig("end_session_endpoint")
    end

    # Get supported ID token signing algorithms from discovery document
    # @return [Array<String>] List of supported algorithms
    def id_token_signing_alg_values_supported
      fetch_discovery&.dig("id_token_signing_alg_values_supported") || []
    end

    # Fetch JWKS with caching
    # @param force [Boolean] Force refresh even if cached
    # @return [Hash, nil] Parsed JWKS document
    def fetch_jwks(force: false)
      uri = jwks_uri
      return nil if uri.blank?

      Discourse.cache.delete(JWKS_CACHE_KEY) if force

      Discourse
        .cache
        .fetch(JWKS_CACHE_KEY, expires_in: JWKS_CACHE_TTL) do
          Rails.logger.info(
            "[LogtoMobileSession] Fetching JWKS from #{uri}, expires in #{JWKS_CACHE_TTL}s",
          )
          fetch_json(uri)
        end
    end

    # Fetch JWKS and raise error if missing or invalid
    # @param force [Boolean] Force refresh even if cached
    # @return [Hash] Parsed JWKS document
    # @raise [ValidationError] If JWKS cannot be fetched
    def jwks!(force: false)
      keys = fetch_jwks(force: force)
      raise ValidationError, "JWKS not available" if keys.nil?
      keys
    end

    # Get list of supported algorithms for JWT validation
    # Derives from JWKS keys or falls back to discovery document
    # @return [Array<String>] List of algorithm names (e.g., ["ES384", "RS256"])
    def algorithms
      # First try to get algorithms from JWKS keys
      jwks = fetch_jwks
      if jwks && jwks["keys"].is_a?(Array)
        algs = jwks["keys"].filter_map { |key| key["alg"] }.uniq
        return algs unless algs.empty?
      end

      # Fall back to discovery document
      algs = id_token_signing_alg_values_supported
      return algs unless algs.empty?

      # Default to RS256 if nothing is specified
      ["RS256"]
    end

    # Invalidate all cached metadata
    # Call this when plugin settings change to force fresh data
    def refresh_all!
      Rails.logger.info("[LogtoMobileSession] Invalidating OIDC metadata cache")
      Discourse.cache.delete(DISCOVERY_CACHE_KEY)
      Discourse.cache.delete(JWKS_CACHE_KEY)

      # Optionally warm the cache if plugin is enabled
      if SiteSetting.logto_mobile_session_enabled
        begin
          discovery!
          jwks!
          Rails.logger.info("[LogtoMobileSession] OIDC metadata cache warmed")
        rescue => e
          Rails.logger.warn("[LogtoMobileSession] Failed to warm cache: #{e.message}")
        end
      end
    end

    private

    # Fetch JSON from URL using Faraday and FinalDestination adapter
    # Mirrors the approach used in discourse-openid-connect
    # @param url [String] URL to fetch
    # @return [Hash] Parsed JSON response
    # @raise [ValidationError] If fetch fails or response is invalid
    def fetch_json(url)
      uri = URI.parse(url)

      connection =
        Faraday.new(url: "#{uri.scheme}://#{uri.host}:#{uri.port}") do |f|
          f.request :url_encoded
          f.adapter FinalDestination::FaradayAdapter
        end

      response = connection.get(uri.path + (uri.query ? "?#{uri.query}" : ""))

      unless response.success?
        raise ValidationError, "Failed to fetch #{url}: HTTP #{response.status}"
      end

      JSON.parse(response.body)
    rescue JSON::ParserError => e
      raise ValidationError, "Invalid JSON response from #{url}: #{e.message}"
    rescue Faraday::Error => e
      raise ValidationError, "Network error fetching #{url}: #{e.message}"
    end

    # Validate that required fields are present in discovery document
    # @param doc [Hash] Discovery document
    # @raise [ValidationError] If required fields are missing
    def validate_discovery_document!(doc)
      required_fields = %w[issuer jwks_uri userinfo_endpoint]
      missing_fields = required_fields.reject { |field| doc[field].present? }

      unless missing_fields.empty?
        raise ValidationError,
              "Discovery document missing required fields: #{missing_fields.join(", ")}"
      end
    end
  end
end
