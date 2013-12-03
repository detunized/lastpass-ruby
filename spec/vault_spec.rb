# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"
require "test_data"

describe LastPass::Vault do
    let(:vault) {
        # Need to crack the Vault open to be able to call new on it for testing purposes
        LastPass::Vault.public_class_method :new

        LastPass::Vault.new LastPass::Blob.new(TEST_BLOB, TEST_KEY_ITERATION_COUNT),
                            TEST_ENCRYPTION_KEY
    }

    describe "#accounts" do
        context "returned accounts" do
            it { expect(vault.accounts).to be_instance_of Array }

            it "should have correct IDs" do
                expect(vault.accounts.map &:id).to eq TEST_ACCOUNTS.map &:id
            end
        end
    end
end
