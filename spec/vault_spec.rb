# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"
require "test_data"

describe LastPass::Vault do
    let(:vault) {
        LastPass::Vault.new LastPass::Blob.new(TEST_BLOB, TEST_KEY_ITERATION_COUNT),
                            TEST_ENCRYPTION_KEY
    }

    describe ".new" do
        it "raises an exception on trucated blob" do
            [1, 10, 100, 1000].each do |i|
                expect {
                    blob = TEST_BLOB[0..(-1 - i)]
                    LastPass::Vault.new LastPass::Blob.new(blob, TEST_KEY_ITERATION_COUNT),
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
        end
    end
end
