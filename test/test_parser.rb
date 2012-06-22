require 'test/unit'
require 'lastpass'

class ParserTest < Test::Unit::TestCase
    @@blob = File.read 'lastpass-blob'

    def setup
        @blob = @@blob
        @parser = LastPass::Parser.parse @blob
    end

    def test_type_is_correct
        assert_kind_of LastPass::Parser, @parser
    end

    def test_parse_fails_with_nil_blob
        assert_raise ArgumentError do
            LastPass::Parser.parse nil
        end
    end

    def test_parse_fails_with_invalid_blob
        assert_raise ArgumentError do
            LastPass::Parser.parse ''
        end

        assert_raise ArgumentError do
            LastPass::Parser.parse 'ABCD'
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
end
