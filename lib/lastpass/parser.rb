require "base64"
require "stringio"

module LastPass
    class Parser
        class << self
            def parse blob
                parser = Parser.new blob
                parser.send :parse # to avoid exposing the private 'parse' method

                parser
            end
        end

        private

        def initialize blob
            @blob = blob
        end

        # Does all the parsing
        def parse
            parse_chunks extract_chunks decode_blob @blob
        end

        # Decodes the blob form base64 to raw
        def decode_blob blob
            if not String === blob
                raise ArgumentError, 'Blob should be a string'
            end

            if blob[0, 4] != 'TFBB'
                raise ArgumentError, 'Blob doesn\'t seem to be base64 encoded'
            end

            decode_base64 blob
        end

        # Splits the blob into the chunks grouped by id
        def extract_chunks blob
            chunks = Hash.new { |hash, key| hash[key] = [] }

            StringIO.open blob do |stream|
                while !stream.eof?
                    chunk = read_chunk stream
                    chunks[chunk[:id]] << chunk[:payload]
                end
            end

            chunks
        end

        # Iterates over the chunks in the stream
        def each_chunk stream
            while !stream.eof?
                yield read_chunk stream
            end
        end

        def parse_chunks raw_chunks
            parsed_chunks = {}

            raw_chunks.each do |id, chunks|
                parse_method = "parse_chunk_#{id}"
                if respond_to? parse_method, true
                    parsed_chunks[id] = chunks.map do |chunk|
                        StringIO.open chunk do |stream|
                            send parse_method, stream
                        end
                    end
                end
            end

            parsed_chunks
        end

        #
        # IO
        #

        def read_chunk stream
            # LastPass blob chunk is made up of 4-byte ID, 4-byte size and payload of that size
            # Example:
            #   0000: 'IDID'
            #   0004: 4
            #   0008: 0xDE 0xAD 0xBE 0xEF
            #   000C: --- Next chunk ---
            id = stream.read 4
            size = read_uint32 stream
            payload = stream.read size

            {:id => id, :size => size, :payload => payload}
        end

        def read_uint32 stream
            stream.read(4).unpack('N').first
        end

        #
        # Decoders
        #

        def decode_base64 data
            Base64.decode64 data
        end
    end
end
