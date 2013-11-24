# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"
require_relative "test_data"

describe LastPass::Parser do
    let(:key_iteration_count) { 5000 }
    let(:blob) { LastPass::Blob.new TEST_BLOB, key_iteration_count }
    let(:padding) { "BEEFFACE"}

    describe ".extract_chunks" do
        context "returned chunks" do
            let(:chunks) { LastPass::Parser.extract_chunks blob }

            it { expect(chunks).to be_instance_of Hash }

            it "all keys are strings" do
                expect(chunks.keys).to match_array TEST_CHUNK_IDS
            end

            it "all values are arrays" do
                expect(chunks.values.map(&:class).uniq).to eq [Array]
            end

            it "all arrays contain only chunks" do
                expect(chunks.values.flat_map { |i| i.map &:class }.uniq).to eq [LastPass::Chunk]
            end

            it "all chunks grouped under correct IDs" do
                expect(
                    chunks.all? { |id, chunk_group| chunk_group.map(&:id).uniq == [id] }
                ).to be_true
            end
        end
    end

    describe ".read_chunk" do
        let(:buffer) { "4944494400000004DEADBEEF" + padding }
        let(:chunk) { LastPass::Chunk.new "IDID", "DEADBEEF".decode_hex }

        it "returns a chunk" do
            with_hex buffer do |io|
                expect(LastPass::Parser.read_chunk io).to eq chunk
            end
        end

        it "reads correct number of bytes" do
            with_hex buffer do |io|
                LastPass::Parser.read_chunk io
                expect(io.pos).to eq 12
            end
        end
    end

    describe ".read_id" do
        let(:id) { "IDID" }
        let(:buffer) { id + padding }

        it "returns an id" do
            with_bytes buffer do |io|
                expect(LastPass::Parser.read_id io).to eq id
            end
        end

        it "reads correct number of bytes" do
            with_bytes buffer do |io|
                LastPass::Parser.read_id io
                expect(io.pos).to eq 4
            end
        end
    end

    describe ".read_size" do
        let(:size) { 4 }
        let(:buffer) { "00000004" + padding }

        it "returns a size" do
            with_hex buffer do |io|
                expect(LastPass::Parser.read_size io).to eq size
            end
        end

        it "reads correct number of bytes" do
            with_hex buffer do |io|
                LastPass::Parser.read_size io
                expect(io.pos).to eq 4
            end
        end
    end

    describe ".read_payload" do
        let(:size) { 4 }
        let(:payload) { "DEADBEEF".decode_hex }
        let(:buffer) { "DEADBEEF" + padding }

        it "returns a payload" do
            with_hex buffer do |io|
                expect(LastPass::Parser.read_payload io, size).to eq payload
            end
        end

        it "reads correct number of bytes" do
            with_hex buffer do |io|
                LastPass::Parser.read_payload io, size
                expect(io.pos).to eq size
            end
        end
    end

    #
    # Helpers
    #

    private

    def with_blob &block
        with_bytes TEST_BLOB, &block
    end

    def with_hex hex, &block
        with_bytes hex.decode_hex, &block
    end

    def with_bytes bytes, &block
        StringIO.open bytes do |io|
            yield io
        end
    end
end
