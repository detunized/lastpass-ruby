require 'test/unit'
require 'lastpass'
require_relative 'helper'

class ParserPrivateTest < Test::Unit::TestCase
    STREAM_PADDING = 'This should be left in the stream!'

    @@blob = File.read 'lastpass-blob'
    @@key = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".decode64

    # The blob is base64 encoded
    @@decoded_blob = Base64.decode64 @@blob

    def setup
        @blob = @@blob
        @key = @@key

        @decoded_blob = @@decoded_blob

        @parser_private_methods = LastPass::Parser.private_instance_methods
        methods = @parser_private_methods
        LastPass::Parser.class_eval { public *methods }

        @parser = LastPass::Parser.new @blob, @key
    end

    def teardown
        methods = @parser_private_methods
        LastPass::Parser.class_eval { private *methods }
    end

    def test_blob
        assert_equal @blob, @parser.instance_variable_get(:@blob)
    end

    def test_encryption_key
        assert_equal @key, @parser.instance_variable_get(:@encryption_key)
    end

    def test_decode_blob
        assert_equal @decoded_blob, @parser.decode_blob(@blob)
    end

    def test_extract_chunks
        chunks = @parser.extract_chunks @decoded_blob

        assert_kind_of Hash, chunks
        chunks.each do |id, chunks_of_one_kind|
            assert_kind_of String, id
            assert_equal 4, id.length
            assert_match /[A-Z]{4}/, id

            assert_kind_of Array, chunks_of_one_kind

            # If an id is present, then there should be at least one chunk of that kind
            assert_operator chunks_of_one_kind.length, :>, 0

            chunks_of_one_kind.each do |chunk|
                assert_kind_of String, chunk
            end
        end
    end

    def test_each_chunk
        # Extract chunks manually
        chunks = []
        StringIO.open @decoded_blob do |stream|
            while !stream.eof?
                chunks << @parser.read_chunk(stream)
            end
        end

        # Extract chunks using 'each_chunk'
        chunks_from_each = []
        StringIO.open @decoded_blob do |stream|
            @parser.each_chunk stream do |chunk|
                chunks_from_each << chunk
            end
        end

        assert_equal chunks, chunks_from_each
    end

    def test_parse_chunks
        raw_chunks = @parser.extract_chunks @decoded_blob
        parsed_chunks = @parser.parse_chunks raw_chunks

        assert_kind_of Hash, parsed_chunks
        parsed_chunks.each do |id, chunks|
            # Parsed chunk id should be one of the original ids
            assert raw_chunks.keys.include? id

            assert_kind_of Array, chunks

            # If chunk type is supported then all of them should be parsed
            assert_equal raw_chunks[id].length, chunks.length
        end
    end

    #
    # IO tests
    #

    def test_read_chunk
        chunk = {:id => 'TEST', :size => 10, :payload => '0123456789'}

        StringIO.open pack_chunk(chunk) do |stream|
            assert_equal chunk, @parser.read_chunk(stream)
            assert stream.eof?
        end

        # Only bytes that make up a chunk should be extracted from the stream
        StringIO.open pack_chunk(chunk) + STREAM_PADDING do |stream|
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

    def test_read_item
        items = [
            {:size => 1, :payload => '0' },
            {:size => 2, :payload => '01' },
            {:size => 10, :payload => '0123456789'},
            {:size => 16, :payload => '0123456789ABCDEF'}
        ]

        # One item in a stream
        items.each do |item|
            StringIO.open pack_item(item) do |stream|
                assert_equal item, @parser.read_item(stream)
                assert stream.eof?
            end
        end

        # All items in one stream
        StringIO.open(items.map { |item| pack_item item }.join) do |stream|
            items.each do |item|
                assert_equal item, @parser.read_item(stream)
            end
            assert stream.eof?
        end

        # All items in one stream + padding (make sure padding is not touched)
        StringIO.open(items.map { |item| pack_item item }.join + STREAM_PADDING) do |stream|
            items.each do |item|
                assert_equal item, @parser.read_item(stream)
            end
            assert_equal STREAM_PADDING, stream.read
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

    def test_decode
        test_data = {
            nil => {'All your base are belong to us' => 'All your base are belong to us'},
            :plain => {'All your base are belong to us' => 'All your base are belong to us'},
            :base64 => {'All your base are belong to us' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVz'}
        }

        test_data.each do |encoding, data|
            data.each do |decoded, encoded|
                assert_equal decoded, @parser.decode(encoded, encoding)
            end
        end

        # Unknown encoding
        assert_raise NoMethodError do
            @parser.decode '', :unknown_encoding
        end
    end

    def test_decode_base64
        test_data = {
            '' => '',
            'All your base are belong to us' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVz',
            'All your base are belong to us.' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzLg==',
            'All your base are belong to us..' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzLi4=',
            'All your base are belong to us...' => 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzLi4u'
        }

        test_data.each do |decoded, encoded|
            assert_equal decoded, @parser.decode_base64(encoded)
        end
    end

    def test_decode_hex
        test_data = {
            '' => '',
            'All your base are belong to us' => '416c6c20796f75722062617365206172652062656c6f6e6720746f207573'
        }

        test_data.each do |decoded, encoded|
            assert_equal decoded, @parser.decode_hex(encoded)
        end
    end

    #
    # Parsing
    #

    def test_parse_itemized_chunk
        decoded_payload = '0123456789'

        info = [
            {:name => :text_plain},
            {:name => :text_base64, :encoding => :base64}
        ]

        items = [
            {:size => 10, :payload => '0123456789'},
            {:size => 16, :payload => 'MDEyMzQ1Njc4OQ=='}
        ]

        StringIO.open(items.map { |item| pack_item item }.join + STREAM_PADDING) do |stream|
            decoded_items = @parser.parse_itemized_chunk stream, info

            assert_kind_of Hash, decoded_items
            assert_equal info.map { |i| i[:name] }.sort, decoded_items.keys.sort

            decoded_items.each do |name, payload|
                assert_equal decoded_payload, payload
            end

            assert_equal STREAM_PADDING, stream.read
        end
    end

    def test_parse_item
        decoded_payload = '0123456789'
        encoded_items = {
            nil => {:size => 10, :payload => '0123456789'},
            :plain => {:size => 10, :payload => '0123456789'},
            :base64 => {:size => 16, :payload => 'MDEyMzQ1Njc4OQ=='}
        }

        encoded_items.each do |encoding, item|
            StringIO.open pack_item(item) do |stream|
                assert_equal decoded_payload, @parser.parse_item(stream, encoding)
            end
        end
    end

    #
    # Helpers
    #

    # Example: chunk = {:id => 'TEST', :size => 10, :payload => '0123456789'}
    def pack_chunk chunk
        [chunk[:id], chunk[:size], chunk[:payload]].pack('a*Na*')
    end

    # Example: item = {:size => 10, :payload => '0123456789'}
    def pack_item item
        [item[:size], item[:payload]].pack('Na*')
    end
end
