# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"
require "test_data"

describe LastPass::Vault do
    let(:vault) {
        LastPass::Vault.new LastPass::Blob.new(TEST_BLOB, TEST_KEY_ITERATION_COUNT, nil),
                            TEST_ENCRYPTION_KEY
    }

    describe ".new" do
        it "raises an exception on trucated blob" do
            [1, 2, 3, 4, 5, 10, 100, 1000].each do |i|
                expect {
                    blob = TEST_BLOB[0..(-1 - i)]
                    LastPass::Vault.new LastPass::Blob.new(blob, TEST_KEY_ITERATION_COUNT, nil),
                                        TEST_ENCRYPTION_KEY
                }.to raise_error LastPass::InvalidResponseError, "Blob is truncated"
            end
        end
    end

    describe "#accounts" do
        context "returned accounts" do
            it { expect(vault.accounts).to be_instance_of Array }

            it "should have correct IDs" do
                expect(vault.accounts.map &:id).to eq TEST_ACCOUNTS.map &:id
            end

            it "should have correct names" do
                expect(vault.accounts.map &:name).to eq TEST_ACCOUNTS.map &:name
            end

            it "should have correct usernames" do
                expect(vault.accounts.map &:username).to eq TEST_ACCOUNTS.map &:username
            end

            it "should have correct passwords" do
                expect(vault.accounts.map &:password).to eq TEST_ACCOUNTS.map &:password
            end

            it "should have correct urls" do
                expect(vault.accounts.map &:url).to eq TEST_ACCOUNTS.map &:url
            end

            it "should have correct notes" do
                expect(vault.accounts.map &:notes).to eq TEST_ACCOUNTS.map &:notes
            end

            it "should have correct groups" do
                expect(vault.accounts.map &:group).to eq TEST_ACCOUNTS.map &:group
            end
        end
    end
end
