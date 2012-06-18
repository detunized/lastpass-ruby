require 'test/unit'
require 'lastpass'

class ParserPrivateTest < Test::Unit::TestCase
    STREAM_PADDING = 'This should be left in the stream!'

    @@blob = File.read 'lastpass-blob'

    # The blob is base64 encoded
    @@decoded_blob = Base64.decode64 @@blob

    def setup
        @blob = @@blob
        @decoded_blob = @@decoded_blob

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
        assert_equal @decoded_blob, @parser.decode_blob(@blob)
    end

    #
    # IO tests
    #

    def test_read_chunk
        chunk = {:id => 'TEST', :size => 10, :payload => '1234567890'}

        StringIO.open [chunk[:id], chunk[:size], chunk[:payload]].pack('a*Na*') do |stream|
            assert_equal chunk, @parser.read_chunk(stream)
            assert stream.eof?
        end

        # Only bytes that make up a chunk should be extracted from the stream
        StringIO.open [chunk[:id], chunk[:size], chunk[:payload], STREAM_PADDING].pack('a*Na*a*') do |stream|
            assert_equal chunk, @parser.read_chunk(stream)
            assert_equal STREAM_PADDING, stream.read
        end

        # The blob should break nicely into chunks
        StringIO.open @decoded_blob do |stream|
            while !stream.eof?
                chunk = @parser.read_chunk stream
                assert_kind_of Hash, chunk
                assert_equal [:id, :payload, :size], chunk.keys.sort
                assert_equal chunk[:size], chunk[:payload].length
            end
        end
    end

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

        # Only bytes that make up numbers should be extracted from the stream
        StringIO.open [0xdeadbeef, 42, 0, STREAM_PADDING].pack('N3a*') do |stream|
            assert_equal 0xdeadbeef, @parser.read_uint32(stream)
            assert_equal 42, @parser.read_uint32(stream)
            assert_equal 0, @parser.read_uint32(stream)
            assert_equal STREAM_PADDING, stream.read
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
