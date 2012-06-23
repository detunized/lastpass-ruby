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
        assert @parser.chunks.keys.include? 'LPAV'
        assert_equal 1, @parser.chunks['LPAV'].length
        assert_equal '9', @parser.chunks['LPAV'][0]
    end

    def test_chunk_ENCU
        assert @parser.chunks.keys.include? 'ENCU'
        assert_equal 1, @parser.chunks['ENCU'].length
        assert_equal 'postlass@gmail.com', @parser.chunks['ENCU'][0]
    end

    def test_chunk_NMAC
        assert @parser.chunks.keys.include? 'NMAC'
        assert_equal 1, @parser.chunks['NMAC'].length
        assert_equal '8', @parser.chunks['NMAC'][0]
    end
end
