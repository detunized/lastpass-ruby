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
end
