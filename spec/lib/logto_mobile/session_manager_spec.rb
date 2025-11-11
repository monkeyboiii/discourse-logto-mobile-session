# frozen_string_literal: true

require 'rails_helper'

describe LogtoMobile::SessionManager do
  subject(:manager) { described_class.new(controller) }

  let(:controller) do
    instance_double(
      'LogtoMobile::SessionController',
      cookies: cookies,
      request: request
    )
  end
  let(:cookies) { instance_double('ActionDispatch::Cookies::CookieJar') }
  let(:request) { instance_double(ActionDispatch::Request, host: 'forum.example.com') }
  let(:user) { Fabricate(:user) }

  before do
    SiteSetting.logto_mobile_session_cookie_ttl = 3_600

    allow(controller).to receive(:log_on_user)
    allow(controller).to receive(:log_off_user)
    allow(cookies).to receive(:encrypted).and_return('_forum_session' => 'cookie-value')
  end

  describe '#create_session' do
    it 'creates a Discourse session and returns the cookie metadata' do
      ttl = 7_200
      SiteSetting.logto_mobile_session_cookie_ttl = ttl
      allow(SiteSetting).to receive(:respond_to?).and_call_original
      allow(SiteSetting).to receive(:respond_to?).with(:cookies_domain).and_return(true)
      allow(SiteSetting).to receive(:cookies_domain).and_return('.example.com')
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new('production'))
      fixed_time = Time.utc(2024, 1, 1, 12, 0, 0)
      allow(Time).to receive(:now).and_return(fixed_time)

      session_cookie = manager.create_session(user)

      expect(controller).to have_received(:log_on_user).with(user)
      expect(session_cookie[:name]).to eq('_forum_session')
      expect(session_cookie[:value]).to eq('cookie-value')
      expect(session_cookie[:domain]).to eq('.example.com')
      expect(session_cookie[:expires_at]).to eq((fixed_time + ttl).iso8601)
      expect(session_cookie[:path]).to eq('/')
      expect(session_cookie[:secure]).to eq(true)
      expect(session_cookie[:http_only]).to eq(true)
      expect(session_cookie[:same_site]).to eq('Lax')
    end
  end

  describe '#destroy_session' do
    it 'logs the user out through the controller' do
      manager.destroy_session

      expect(controller).to have_received(:log_off_user)
    end
  end

  describe '#extract_cookie_domain' do
    it 'prefers the configured cookies_domain setting when present' do
      allow(SiteSetting).to receive(:respond_to?).and_call_original
      allow(SiteSetting).to receive(:respond_to?).with(:cookies_domain).and_return(true)
      allow(SiteSetting).to receive(:cookies_domain).and_return('.custom-domain.com')

      domain = manager.send(:extract_cookie_domain)

      expect(domain).to eq('.custom-domain.com')
    end

    it 'derives the apex domain in production when no setting is provided' do
      allow(SiteSetting).to receive(:respond_to?).and_call_original
      allow(SiteSetting).to receive(:respond_to?).with(:cookies_domain).and_return(true)
      allow(SiteSetting).to receive(:cookies_domain).and_return(nil)
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new('production'))
      allow(request).to receive(:host).and_return('community.secure.example.co.uk')

      domain = manager.send(:extract_cookie_domain)

      expect(domain).to eq('.example.co.uk')
    end

    it 'falls back to the request host for localhost or non-production environments' do
      allow(SiteSetting).to receive(:respond_to?).and_call_original
      allow(SiteSetting).to receive(:respond_to?).with(:cookies_domain).and_return(true)
      allow(SiteSetting).to receive(:cookies_domain).and_return(nil)
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new('test'))
      allow(request).to receive(:host).and_return('localhost')

      domain = manager.send(:extract_cookie_domain)

      expect(domain).to eq('localhost')
    end
  end
end
