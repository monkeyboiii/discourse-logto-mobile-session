# frozen_string_literal: true

require 'rails_helper'

describe LogtoMobile::UserProvisioner do
  let(:base_user_info) do
    {
      sub: 'logto-sub-123',
      email: 'jane@example.com',
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
      expect(user.email).to eq('jane@example.com')
      expect(user.username).to eq('janesmith')
      expect(user.name).to eq('Jane Smith')
      expect(user.active).to eq(true)
      expect(user.approved).to eq(true)
      expect(user.custom_fields['logto_sub']).to eq('logto-sub-123')
      expect(user.custom_fields['logto_email_verified']).to eq('t')

      associated_account = UserAssociatedAccount.find_by(
        user_id: user.id,
        provider_name: 'oidc'
      )
      expect(associated_account).to be_present
      expect(associated_account.provider_uid).to eq('logto-sub-123')

      expect(Jobs).to have_received(:enqueue).with(
        :download_avatar_from_url,
        satisfy do |payload|
          payload[:url] == 'https://cdn.example.com/avatar.png' &&
            payload[:user_id] == user.id &&
            payload[:override_gravatar] == false
        end
      )
    end

    it 'updates an existing user matched by email' do
      existing_user = Fabricate(:user, email: 'existing@example.com', name: 'Old Name', username: 'existing')
      allow(Jobs).to receive(:enqueue)

      user_info[:email] = existing_user.email
      user_info[:name] = 'Updated Name'
      user_info[:username] = 'ignored'

      provisioned = provisioner.provision
      existing_user.reload

      expect(provisioned.id).to eq(existing_user.id)
      expect(existing_user.name).to eq('Updated Name')
      expect(existing_user.username).to eq('existing')
      expect(existing_user.custom_fields['logto_sub']).to eq('logto-sub-123')
      expect(existing_user.custom_fields['logto_last_auth']).to be_present

      # Check that name change job was enqueued
      expect(Jobs).to have_received(:enqueue).with(
        :change_display_name,
        satisfy { |payload| payload[:new_name] == 'Updated Name' && payload[:old_name] == 'Old Name' }
      )

      # Check that avatar download was enqueued
      expect(Jobs).to have_received(:enqueue).with(
        :download_avatar_from_url,
        satisfy { |payload| payload[:url] == 'https://cdn.example.com/avatar.png' }
      )
    end

    it 'creates UserAssociatedAccount for existing user without one' do
      existing_user = Fabricate(:user, email: 'existing@example.com')
      allow(Jobs).to receive(:enqueue)

      user_info[:email] = existing_user.email

      provisioned = provisioner.provision

      expect(provisioned.id).to eq(existing_user.id)

      # Verify association was created
      association = UserAssociatedAccount.find_by(
        user_id: existing_user.id,
        provider_name: 'oidc'
      )
      expect(association).to be_present
      expect(association.provider_uid).to eq('logto-sub-123')
      expect(association.info['email']).to eq('existing@example.com')
      expect(association.credentials).to eq({})
      expect(association.last_used).to be_present
    end

    it 'matches existing users via their stored Logto subject' do
      matched = Fabricate(:user, email: 'legacy@example.com', username: 'legacy')
      matched.custom_fields['logto_sub'] = 'logto-sub-123'
      matched.save_custom_fields(true)
      allow(Jobs).to receive(:enqueue)

      user_info[:email] = 'legacy@example.com'

      provisioned = provisioner.provision

      expect(provisioned.id).to eq(matched.id)
      expect(Jobs).not_to have_received(:enqueue).with(:download_avatar_from_url, anything)
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
      expect(Jobs).not_to have_received(:enqueue).with(:download_avatar_from_url, anything)
    end

    it 'wraps ActiveRecord::RecordInvalid errors with ProvisioningError' do
      record_invalid = ActiveRecord::RecordInvalid.new(User.new)
      allow(provisioner).to receive(:find_existing_user).and_return(nil)
      allow(provisioner).to receive(:create_new_user).and_raise(record_invalid)

      expect { provisioner.provision }.to raise_error(
        LogtoMobile::ProvisioningError,
        /Failed to provision user/
      )
    end

    context 'duplicate association handling' do
      it 'destroys old association when user switches Logto accounts' do
        user = Fabricate(:user, email: 'user@example.com')
        allow(Jobs).to receive(:enqueue)

        # First login with Logto account A
        old_association = UserAssociatedAccount.create!(
          provider_name: 'oidc',
          provider_uid: 'old-logto-sub-999',
          user: user,
          info: { email: user.email },
          credentials: {},
          extra: {},
          last_used: 1.day.ago
        )

        # User deletes Logto account A and creates new account B with same email
        user_info[:email] = user.email
        user_info[:sub] = 'new-logto-sub-123'

        provisioned = provisioner.provision

        expect(provisioned.id).to eq(user.id)

        # Old association should be destroyed
        expect(UserAssociatedAccount.exists?(old_association.id)).to eq(false)

        # New association should exist
        new_association = UserAssociatedAccount.find_by(
          user_id: user.id,
          provider_name: 'oidc'
        )
        expect(new_association).to be_present
        expect(new_association.provider_uid).to eq('new-logto-sub-123')
      end
    end

    context 'UserAssociatedAccount field population' do
      it 'populates all required fields correctly' do
        allow(Jobs).to receive(:enqueue)

        user = provisioner.provision

        association = UserAssociatedAccount.find_by(
          user_id: user.id,
          provider_name: 'oidc'
        )

        # Check info field
        expect(association.info).to be_a(Hash)
        expect(association.info['email']).to eq('jane@example.com')
        expect(association.info['name']).to eq('Jane Smith')
        expect(association.info['picture']).to eq('https://cdn.example.com/avatar.png')

        # Check credentials field
        expect(association.credentials).to be_a(Hash)
        expect(association.credentials).to eq({})

        # Check extra field
        expect(association.extra).to be_a(Hash)
        expect(association.extra['email_verified']).to eq(true)
        expect(association.extra['created_via']).to eq('mobile_session_exchange')

        # Check last_used
        expect(association.last_used).to be_within(5.seconds).of(Time.zone.now)
      end
    end

    context 'staged user conversion' do
      it 'converts staged users to real users' do
        staged_user = Fabricate(:user, email: 'staged@example.com', staged: true)
        allow(Jobs).to receive(:enqueue)

        user_info[:email] = staged_user.email

        provisioned = provisioner.provision
        staged_user.reload

        expect(provisioned.id).to eq(staged_user.id)
        expect(staged_user.staged).to eq(false)
        expect(staged_user.active).to eq(false) # Unstaged users are inactive initially
      end
    end

    context 'profile sync' do
      it 'syncs bio and location from Logto for new users' do
        user_info[:bio] = 'Software developer'
        user_info[:location] = 'San Francisco'
        allow(Jobs).to receive(:enqueue)

        user = provisioner.provision

        profile = user.user_profile
        expect(profile.bio_raw).to eq('Software developer')
        expect(profile.location).to eq('San Francisco')
      end

      it 'does not override existing bio and location' do
        existing_user = Fabricate(:user, email: 'existing@example.com')
        existing_user.user_profile.update!(
          bio_raw: 'Existing bio',
          location: 'New York'
        )
        allow(Jobs).to receive(:enqueue)

        user_info[:email] = existing_user.email
        user_info[:bio] = 'New bio from Logto'
        user_info[:location] = 'Los Angeles'

        provisioner.provision
        existing_user.reload

        # Should NOT override existing values
        expect(existing_user.user_profile.bio_raw).to eq('Existing bio')
        expect(existing_user.user_profile.location).to eq('New York')
      end

      it 'fills blank profile fields from Logto' do
        existing_user = Fabricate(:user, email: 'existing@example.com')
        allow(Jobs).to receive(:enqueue)

        user_info[:email] = existing_user.email
        user_info[:bio] = 'Bio from Logto'
        user_info[:location] = 'Seattle'

        provisioner.provision
        existing_user.reload

        # Should fill blank fields
        expect(existing_user.user_profile.bio_raw).to eq('Bio from Logto')
        expect(existing_user.user_profile.location).to eq('Seattle')
      end
    end

    context 'avatar override settings' do
      it 'respects auth_overrides_avatar setting when false' do
        SiteSetting.auth_overrides_avatar = false

        existing_user = Fabricate(:user, email: 'existing@example.com')
        # Simulate user has custom avatar
        allow_any_instance_of(User).to receive_message_chain(:user_avatar, :custom_upload_id).and_return(123)
        allow(Jobs).to receive(:enqueue)

        user_info[:email] = existing_user.email
        user_info[:picture] = 'https://logto.com/new-avatar.png'

        provisioner.provision

        # Should NOT enqueue avatar download because user has custom avatar and override is disabled
        expect(Jobs).not_to have_received(:enqueue).with(:download_avatar_from_url, anything)
      end

      it 'downloads avatar when auth_overrides_avatar is true' do
        SiteSetting.auth_overrides_avatar = true

        existing_user = Fabricate(:user, email: 'existing@example.com')
        # Simulate user has custom avatar
        allow_any_instance_of(User).to receive_message_chain(:user_avatar, :custom_upload_id).and_return(123)
        allow(Jobs).to receive(:enqueue)

        user_info[:email] = existing_user.email
        user_info[:picture] = 'https://logto.com/new-avatar.png'

        provisioner.provision

        # SHOULD enqueue avatar download even with custom avatar because override is enabled
        expect(Jobs).to have_received(:enqueue).with(
          :download_avatar_from_url,
          satisfy { |payload| payload[:url] == 'https://logto.com/new-avatar.png' }
        )
      end

      it 'downloads avatar for users without custom avatar' do
        SiteSetting.auth_overrides_avatar = false

        existing_user = Fabricate(:user, email: 'existing@example.com')
        allow(Jobs).to receive(:enqueue)

        user_info[:email] = existing_user.email
        user_info[:picture] = 'https://logto.com/avatar.png'

        provisioner.provision

        # SHOULD enqueue avatar download because user has no custom avatar
        expect(Jobs).to have_received(:enqueue).with(
          :download_avatar_from_url,
          satisfy { |payload| payload[:url] == 'https://logto.com/avatar.png' }
        )
      end
    end
  end
end
