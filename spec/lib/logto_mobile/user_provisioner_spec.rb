# frozen_string_literal: true

require 'rails_helper'

describe LogtoMobile::UserProvisioner do
  let(:base_user_info) do
    {
      sub: 'logto-sub-123',
      email: '[email protected]',
      email_verified: true,
      name: 'Jane Smith',
      username: 'janesmith',
      picture: 'https://cdn.example.com/avatar.png'
    }
  end

  let(:user_info) { base_user_info.deep_dup }
  let(:provisioner) { described_class.new(user_info) }

  before do
    SiteSetting.logto_mobile_session_auto_approve_users = true
  end

  describe '#provision' do
    it 'creates a new activated Discourse user with associated OIDC account' do
      allow(Jobs).to receive(:enqueue)

      user = provisioner.provision

      expect(user).to be_persisted
      expect(user.email).to eq('[email protected]')
      expect(user.username).to eq('janesmith')
      expect(user.name).to eq('Jane Smith')
      expect(user.active).to eq(true)
      expect(user.approved).to eq(true)
      expect(user.custom_fields['logto_sub']).to eq('logto-sub-123')
      expect(user.custom_fields['logto_email_verified']).to eq(true)

      associated_account = UserAssociatedAccount.find_by(
        user_id: user.id,
        provider_name: 'oidc'
      )
      expect(associated_account).to be_present
      expect(associated_account.provider_uid).to eq('logto-sub-123')

      expect(Jobs).to have_received(:enqueue).with(
        :download_avatar_from_url,
        hash_including(
          url: 'https://cdn.example.com/avatar.png',
          user_id: user.id
        )
      )
    end

    it 'updates an existing user matched by email' do
      existing_user = Fabricate(:user, email: '[email protected]', name: 'Old Name', username: 'existing')
      allow(Jobs).to receive(:enqueue)

      user_info[:name] = 'Updated Name'
      user_info[:username] = 'ignored'

      provisioned = provisioner.provision
      existing_user.reload

      expect(provisioned.id).to eq(existing_user.id)
      expect(existing_user.name).to eq('Updated Name')
      expect(existing_user.username).to eq('existing')
      expect(existing_user.custom_fields['logto_sub']).to eq('logto-sub-123')
      expect(existing_user.custom_fields['logto_last_auth']).to be_present
      expect(Jobs).not_to have_received(:enqueue)
    end

    it 'matches existing users via their stored Logto subject' do
      matched = Fabricate(:user, email: '[email protected]', username: 'legacy')
      matched.custom_fields['logto_sub'] = 'logto-sub-123'
      matched.save_custom_fields(true)
      allow(Jobs).to receive(:enqueue)

      user_info[:email] = '[email protected]'

      provisioned = provisioner.provision

      expect(provisioned.id).to eq(matched.id)
      expect(Jobs).not_to have_received(:enqueue)
    end

    it 'generates a unique username when the preferred one is taken' do
      Fabricate(:user, username: 'janesmith')
      Fabricate(:user, username: 'janesmith1')
      allow(Jobs).to receive(:enqueue)

      user = provisioner.provision

      expect(user.username).to eq('janesmith2')
    end

    it 'falls back to a random username when none is provided' do
      user_info[:username] = ''
      user_info[:picture] = nil
      allow(SecureRandom).to receive(:hex).and_call_original
      allow(SecureRandom).to receive(:hex).with(8).and_return('abc12345')
      allow(Jobs).to receive(:enqueue)

      user = provisioner.provision

      expect(user.username).to eq('user_abc12345')
      expect(Jobs).not_to have_received(:enqueue)
    end
  end
end
