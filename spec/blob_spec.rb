# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Blob do
    let(:bytes) { "TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5".decode64 }
    let(:key_iteration_count) { 500 }
    let(:username) { "postlass@gmail.com" }
    let(:password) { "pl1234567890" }
    let(:encryption_key) { "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".decode64 }

    subject { LastPass::Blob.new bytes, key_iteration_count }

    its(:bytes) { should eq bytes }
    its(:key_iteration_count) { should eq key_iteration_count }

    describe "#encryption_key" do
        it "returns encryption key" do
            expect(subject.encryption_key username, password).to eq encryption_key
        end
    end
end
