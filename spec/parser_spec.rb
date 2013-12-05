# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"
require_relative "test_data"

describe LastPass::Parser do
    let(:key_iteration_count) { 5000 }
    let(:blob) { LastPass::Blob.new TEST_BLOB, key_iteration_count }
    let(:padding) { "BEEFFACE"}
    let(:encryption_key) { "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".decode64 }

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
                .map { |i| LastPass::Parser.parse_account i, TEST_ENCRYPTION_KEY }
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

    describe ".decode_hex" do
        it "decodes hex" do
            expect(LastPass::Parser.decode_hex "")
                .to eq ""

            expect(LastPass::Parser.decode_hex "00ff")
                .to eq "\x00\xFF"

            expect(LastPass::Parser.decode_hex "00010203040506070809")
                .to eq "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"

            expect(LastPass::Parser.decode_hex "000102030405060708090a0b0c0d0e0f")
                .to eq "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"

            expect(LastPass::Parser.decode_hex "8af633933e96a3c3550c2734bd814195")
                .to eq "\x8A\xF6\x33\x93\x3E\x96\xA3\xC3\x55\x0C\x27\x34\xBD\x81\x41\x95"
        end

        it "raises exception on odd length" do
            expect { LastPass::Parser.decode_hex "0" }
                .to raise_error ArgumentError, "Input length must be multple of 2"
        end

        it "raises exception on invalid characters" do
            expect { LastPass::Parser.decode_hex "xz" }
                .to raise_error ArgumentError, "Input contains invalid characters"
        end
    end

    describe ".decode_base64" do
        it "decodes base64" do
            def check base64, plain
                expect(LastPass::Parser.decode_base64 base64).to eq plain
            end

            check "", ""
            check "YQ==", "a"
            check "YWI=", "ab"
            check "YWJj", "abc"
            check "YWJjZA==", "abcd"
        end
    end

    describe ".decode_aes256_auto" do
        def check encoded, decoded
            expect(LastPass::Parser.decode_aes256_auto encoded, encryption_key)
                .to eq decoded
        end

        it "decodes a blank string" do
            check "", ""
        end

        it "decodes ECB/plain string" do
            check "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM=".decode64,
                   "All your base are belong to us"
        end

        it "decodes ECB/base64 string" do
            check "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM=",
                   "All your base are belong to us"
        end

        it "decodes CBC/plain string" do
            check "IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA==".decode64,
                   "All your base are belong to us"
        end

        it "decodes CBC/base64 string" do
            check "!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=",
                   "All your base are belong to us"
        end
    end

    describe ".decode_aes256_ecb_plain" do
        def check encoded, decoded
            expect(LastPass::Parser.decode_aes256_ecb_plain encoded.decode64, encryption_key)
                .to eq decoded
        end

        it "decodes a blank string" do
            check "", ""
        end

        it "decodes a short string" do
            check "8mHxIA8rul6eq72a/Gq2iw==", "0123456789"
        end

        it "decodes a long string" do
            check "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM=", "All your base are belong to us"
        end
    end

    describe ".decode_aes256_ecb_base64" do
        def check encoded, decoded
            expect(LastPass::Parser.decode_aes256_ecb_base64 encoded, encryption_key)
                .to eq decoded
        end

        it "decodes a blank string" do
            check "", ""
        end

        it "decodes a short string" do
            check "8mHxIA8rul6eq72a/Gq2iw==", "0123456789"
        end

        it "decodes a long string" do
            check "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM=", "All your base are belong to us"
        end
    end

    describe ".decode_aes256_cbc_plain" do
        def check encoded, decoded
            expect(LastPass::Parser.decode_aes256_cbc_plain encoded.decode64, encryption_key)
                .to eq decoded
        end

        it "decodes a blank string" do
            check "", ""
        end

        it "decodes a short string" do
            check "IQ+hiIy0vGG4srsHmXChe3ehWc/rYPnfiyqOG8h78DdX", "0123456789"
        end

        it "decodes a long string" do
            check "IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA==",
                  "All your base are belong to us"
        end
    end

    describe ".decode_aes256_cbc_base64" do
        def check encoded, decoded
            expect(LastPass::Parser.decode_aes256_cbc_base64 encoded, encryption_key)
                .to eq decoded
        end

        it "decodes a blank string" do
            check "", ""
        end

        it "decodes a short string" do
            check "!6TZb9bbrqpocMaNgFjrhjw==|f7RcJ7UowesqGk+um+P5ug==", "0123456789"
        end

        it "decodes a long string" do
            check "!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=",
                  "All your base are belong to us"
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
