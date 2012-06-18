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

    #
    # IO tests
    #

    def test_read_uint32
        numbers = [0, 1, 10, 1000, 10000, 100000, 1000000, 10000000, 100000000, 0x7fffffff, 0xffffffff]

        # Pack numbers into individual streams
        numbers.each do |number|
            StringIO.open [number].pack('N') do |stream|
                assert_equal number, @parser.read_uint32(stream)
                assert stream.eof?
            end
        end

        # Pack all numbers into one stream
        StringIO.open numbers.pack('N*') do |stream|
            numbers.each do |number|
                assert_equal number, @parser.read_uint32(stream)
            end
            assert stream.eof?
        end

        # Test that only required bytes are extracted from the stream
        StringIO.open [0xdeadbeef, 42, 0, 'This should be left in the stream!'].pack('N3a*') do |stream|
            assert_equal 0xdeadbeef, @parser.read_uint32(stream)
            assert_equal 42, @parser.read_uint32(stream)
            assert_equal 0, @parser.read_uint32(stream)
            assert_equal 'This should be left in the stream!', stream.read
        end
    end

    #
    # decode_* tests
    #

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
