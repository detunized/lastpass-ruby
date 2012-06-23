require 'test/unit'
require 'lastpass'
require_relative 'helper'

class ParserTest < Test::Unit::TestCase
    @@blob = File.read 'lastpass-blob'
    @@key = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".decode64

    def setup
        @blob = @@blob
        @key = @@key
        @parser = LastPass::Parser.parse @blob, @key
    end

    def test_type_is_correct
        assert_kind_of LastPass::Parser, @parser
    end

    def test_parse_fails_with_nil_blob
        assert_raise ArgumentError do
            LastPass::Parser.parse nil, @key
        end
    end

    def test_parse_fails_with_invalid_blob
        assert_raise ArgumentError do
            LastPass::Parser.parse '', @key
        end

        assert_raise ArgumentError do
            LastPass::Parser.parse 'ABCD', @key
        end
    end

    def test_chunks
        assert_kind_of Hash, @parser.chunks
        @parser.chunks.each do |id, chunks|
            assert_kind_of String, id
            assert_equal 4, id.length
            assert_match /[A-Z]{4}/, id

            assert_kind_of Array, chunks
            assert_operator chunks.length, :>, 0
        end
    end

    def test_chunk_LPAV
        check_only_one_chunk 'LPAV', '9'
    end

    def test_chunk_ENCU
        check_only_one_chunk 'ENCU', 'postlass@gmail.com'
    end

    def test_chunk_NMAC
        check_only_one_chunk 'NMAC', '8'
    end

    #
    # Helpers
    #

    def check_only_one_chunk id, value
        assert @parser.chunks.keys.include? id
        assert_equal 1, @parser.chunks[id].length
        assert_equal value, @parser.chunks[id][0]
    end
end
