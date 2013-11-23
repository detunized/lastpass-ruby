# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Parser do
    let(:blob) { File.read "lastpass-blob" }
    let(:key) { "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".decode64 }
    let(:parser) { LastPass::Parser.parse blob, key }

    describe "parse" do
        it "returns Parser" do
            expect(parser).to be_instance_of LastPass::Parser
        end

        it "raises an exception for nil blob" do
            expect { LastPass::Parser.parse nil, key }.to raise_error ArgumentError
        end

        it "raises an exception for empty blob" do
            expect { LastPass::Parser.parse "", key }.to raise_error ArgumentError
        end

        it "raises an exception for invalid blob" do
            expect { LastPass::Parser.parse "ABCD", key }.to raise_error ArgumentError
        end
    end

    it "returns chunks as a hash" do
        expect(parser.chunks).to be_instance_of Hash
    end

    it "contains chunks with correct structure" do
        parser.chunks.each do |id, chunks|
            expect(id).to be_instance_of String
            expect(id).to match /^[A-Z]{4}$/

            expect(chunks).to be_instance_of Array
            expect(chunks.size).to be > 0
        end
    end

    it "contains LPAV chunk" do
        check_single_chunk "LPAV", "9"
    end

    it "contains ENCU chunk" do
        check_single_chunk "ENCU", "postlass@gmail.com"
    end

    it "contains NMAC chunk" do
        check_single_chunk "NMAC", "8"
    end

    #
    # Helpers
    #

    private

    def check_single_chunk id, value
        parser.chunks.keys.should include id

        chunks = parser.chunks[id]
        chunks.size.should == 1
        chunks.first.should == value
    end
end
