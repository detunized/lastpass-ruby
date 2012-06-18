require 'test/unit'
require 'lastpass'

class ParserPrivateTest < Test::Unit::TestCase
    @@blob = File.read 'lastpass-blob'

    def setup
        @blob = @@blob

        @parser_private_methods = LastPass::Parser.private_instance_methods
        methods = @parser_private_methods
        LastPass::Parser.class_eval { public *methods }

        @parser = LastPass::Parser.new @blob
    end

    def teardown
        methods = @parser_private_methods
        LastPass::Parser.class_eval { private *methods }
    end

    def test_decode_blob
        assert_equal 'LPAV', @parser.decode_blob(@blob)[0, 4]
    end

    def test_decode_base64
        test_data = {
            'All your base are belong to us' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVz',
            'All your base are belong to us.' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzLg==',
            'All your base are belong to us..' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzLi4=',
            'All your base are belong to us...' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzLi4u'
        }

        test_data.each do |decoded, encoded|
            assert_equal decoded, @parser.decode_base64(encoded)
        end
    end
end
