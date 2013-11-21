# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Blob do
    let(:bytes) { "TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5" }
    let(:key_iteration_count) { 5000 }
    let(:blob) { LastPass::Blob.new bytes, key_iteration_count }

    describe "#bytes" do
        it "returns bytes" do
            expect(blob.bytes).to eq bytes
        end

        it "returns key iteration count" do
            expect(blob.key_iteration_count).to eq key_iteration_count
        end
    end
end
