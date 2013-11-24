# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Parser do
    let(:blob_bytes) { File.read("lastpass-blob").decode64 }
    let(:key_iteration_count) { 5000 }
    let(:blob) { LastPass::Blob.new blob_bytes, key_iteration_count }

    describe ".extract_chunks" do
        context "returned chunks" do
            let(:chunks) { LastPass::Parser.extract_chunks blob }

            it { expect(chunks).to be_instance_of Hash }

            it "has correct size" do
                expect(chunks.size).to eq 21
            end

            it "all keys are strings" do
                expect(chunks.keys.map(&:class).uniq).to eq [String]
            end

            it "all values are arrays" do
                expect(chunks.values.map(&:class).uniq).to eq [Array]
            end

            it "all arrays contain only chunks" do
                expect(chunks.values.flat_map { |i| i.map &:class }.uniq).to eq [LastPass::Chunk]
            end
        end
    end
end
