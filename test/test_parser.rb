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
end
