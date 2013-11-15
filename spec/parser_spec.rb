require "spec_helper"

describe LastPass::Parser do
    before :all do
        @blob = File.read 'lastpass-blob'
        @key = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".decode64
        @parser = LastPass::Parser.parse @blob, @key
    end

    describe "parse" do
        it "returns Parser" do
            @parser.should be_an_instance_of LastPass::Parser
        end

        it "raises an exception for nil blob" do
            lambda { LastPass::Parser.parse nil, @key }.should raise_error ArgumentError
        end

        it "raises an exception for empty blob" do
            lambda { LastPass::Parser.parse "", @key }.should raise_error ArgumentError
        end

        it "raises an exception for invalid blob" do
            lambda { LastPass::Parser.parse "ABCD", @key }.should raise_error ArgumentError
        end
    end

    it "returns chunks as a hash" do
        @parser.chunks.should be_an_instance_of Hash
    end

    it "contains chunks with correct structure" do
        @parser.chunks.each do |id, chunks|
            id.should be_an_instance_of String
            id.size.should == 4
            id.should match /^[A-Z]{4}$/

            chunks.should be_an_instance_of Array
            chunks.size.should > 0
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

    def check_single_chunk id, value
        @parser.chunks.keys.should include id

        chunks = @parser.chunks[id]
        chunks.size.should == 1
        chunks.first.should == value
    end
end
