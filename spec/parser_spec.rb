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

    describe ".parse_account" do
        let(:accounts) {
            LastPass::Parser
                .extract_chunks(blob)["ACCT"]
                .map { |i| LastPass::Parser.parse_account i }
        }

        it "parses accounts" do
            expect(accounts.map &:id).to eq TEST_ACCOUNTS.map &:id
        end
    end

    describe ".read_chunk" do
        it "returns a chunk" do
            with_hex "4142434400000004DEADBEEF" + padding do |io|
                expect(LastPass::Parser.read_chunk io).to eq LastPass::Chunk.new("ABCD", "DEADBEEF".decode_hex)
                expect(io.pos).to eq 12
            end
        end
    end

    describe ".read_item" do
        it "returns an item" do
            with_hex "00000004DEADBEEF" + padding do |io|
                expect(LastPass::Parser.read_item io).to eq "DEADBEEF".decode_hex
                expect(io.pos).to eq 8
            end
        end
    end

    describe ".skip_item" do
        it "skips an empty item" do
            with_hex "00000000" + padding do |io|
                LastPass::Parser.skip_item io
                expect(io.pos).to eq 4
            end
        end

        it "skips a non-empty item" do
            with_hex "00000004DEADBEEF" + padding do |io|
                LastPass::Parser.skip_item io
                expect(io.pos).to eq 8
            end
        end
    end

    describe ".read_id" do
        it "returns an id" do
            with_bytes "ABCD" + padding do |io|
                expect(LastPass::Parser.read_id io).to eq "ABCD"
                expect(io.pos).to eq 4
            end
        end
    end

    describe ".read_size" do
        it "returns a size" do
            with_hex "DEADBEEF" + padding do |io|
                expect(LastPass::Parser.read_size io).to eq 0xDEADBEEF
                expect(io.pos).to eq 4
            end
        end
    end

    describe ".read_payload" do
        it "returns a payload" do
            with_hex "FEEDDEADBEEF" + padding do |io|
                expect(LastPass::Parser.read_payload io, 6).to eq "FEEDDEADBEEF".decode_hex
                expect(io.pos).to eq 6
            end
        end
    end

    describe ".read_uint32" do
        it "returns a number" do
            with_hex "DEADBEEF" + padding do |io|
                expect(LastPass::Parser.read_size io).to eq 0xDEADBEEF
                expect(io.pos).to eq 4
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
