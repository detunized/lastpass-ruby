# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "base64"
require "openssl"
require "stringio"

require_relative "chunk"

module LastPass
    class Parser
        class << self
            def parse blob, encryption_key
                parser = Parser.new blob, encryption_key
                parser.send :parse # to avoid exposing the private 'parse' method

                parser
            end
        end

        attr_reader :chunks

        private

        def initialize blob, encryption_key
            @blob = blob
            @encryption_key = encryption_key
        end

        # Does all the parsing
        def parse
            @chunks = parse_chunks extract_chunks decode_blob @blob
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

        def read_item stream
            # An item in an itemized chunk is made up of a size and the payload
            # Example:
            #   0000: 4
            #   0004: 0xDE 0xAD 0xBE 0xEF
            #   0008: --- Next item ---
            size = read_uint32 stream
            payload = stream.read size

            {:size => size, :payload => payload}
        end

        def read_uint32 stream
            stream.read(4).unpack('N').first
        end

        #
        # Decoders
        #

        # Allowed encodings:
        #  - nil or :plain
        #  - :base64
        def decode data, encoding = nil
            if encoding.nil? || encoding == :plain
                data
            else
                send "decode_#{encoding}", data
            end
        end

        def decode_base64 data
            # TODO: Check for input validity
            Base64.decode64 data
        end

        def decode_hex data
            # TODO: Check for input validity
            data.scan(/../).map { |i| i.to_i 16 }.pack "c*"
        end

        # Guesses AES encoding/cipher from the length of the data.
        def decode_aes256 data
            length = data.length
            length16 = length % 16
            length64 = length % 64

            if length == 0
                ''
            elsif length16 == 0
                decode_aes256_ecb_plain data
            elsif length64 == 0 || length64 == 24 || length64 == 44
                decode_aes256_ecb_base64 data
            elsif length16 == 1
                decode_aes256_cbc_plain data
            elsif length64 == 6 || length64 == 26 || length64 == 50
                decode_aes256_cbc_base64 data
            else
                raise RuntimeError, "'#{data.inspect}' doesn't seem to be AES-256 encrypted"
            end
        end

        def decode_aes256_ecb_plain data
            if data.empty?
                ''
            else
                _decode_aes256 :ecb, '', data
            end
        end

        def decode_aes256_ecb_base64 data
            decode_aes256_ecb_plain decode_base64 data
        end

        # LastPass AES-256/CBC encryted string starts with '!'.
        # Next 16 bytes are the IV for the cipher.
        # And the rest is the encrypted payload.
        def decode_aes256_cbc_plain data
            if data.empty?
                ''
            else
                # TODO: Check for input validity!
                _decode_aes256 :cbc, data[1, 16], data[17..-1]
            end
        end

        # LastPass AES-256/CBC/base64 encryted string starts with '!'.
        # Next 24 bytes are the base64 encoded IV for the cipher.
        # Then comes the '|'.
        # And the rest is the base64 encoded encrypted payload.
        def decode_aes256_cbc_base64 data
            if data.empty?
                ''
            else
                # TODO: Check for input validity!
                _decode_aes256 :cbc, decode_base64(data[1, 24]), decode_base64(data[26..-1])
            end
        end

        # Hidden, so it's not discoverable as 'decode_*'.
        # Allowed ciphers are :ecb and :cbc.
        # If for :ecb iv is not used and should be set to ''.
        def _decode_aes256 cipher, iv, data
            aes = OpenSSL::Cipher::Cipher.new "aes-256-#{cipher}"
            aes.decrypt
            aes.key = @encryption_key
            aes.iv = iv
            aes.update(data) + aes.final
        end

        #
        # Parsing
        #

        # Generic itemized chunk parser.  Info parameter should look like this:
        # [
        #   {:name => 'item_name1'},
        #   {:name => 'item_name2', :encoding => :hex},
        #   {:name => 'item_name3', :encoding => :aes256}
        # ]
        def parse_itemized_chunk stream, info
            chunk = {}

            info.each do |item_info|
                chunk[item_info[:name]] = parse_item stream, item_info[:encoding]
            end

            chunk
        end

        # Itemized chunk item parser. For the list of allowed encodings see 'decode'.
        # Returns decoded payload.
        def parse_item stream, encoding = nil
            decode read_item(stream)[:payload], encoding
        end

        #
        # Chunk parsers
        #

        # 'LPAV' chunk seems to be storing some kind of version information
        def parse_chunk_LPAV stream
            stream.read
        end

        # 'ENCU' chunk contains encrypted user name
        def parse_chunk_ENCU stream
            decode_aes256 stream.read
        end

        # 'NMAC' chunk contains number of accounts
        def parse_chunk_NMAC stream
            stream.read
        end

        # 'ACCT' chunk contains account information
        def parse_chunk_ACCT stream
            parse_itemized_chunk stream, [
                {:name => :id},
                {:name => :name, :encoding => :aes256},
                {:name => :group, :encoding => :aes256},
                {:name => :url, :encoding => :hex},
                {:name => :extra},
                {:name => :favorite},
                {:name => :shared_from_id},
                {:name => :username, :encoding => :aes256},
                {:name => :password, :encoding => :aes256},
                {:name => :password_protected},
                {:name => :generated_password},
                {:name => :sn}, # ?
                {:name => :last_touched},
                {:name => :auto_login},
                {:name => :never_autofill},
                {:name => :realm_data},
                {:name => :fiid}, # ?
                {:name => :custom_js},
                {:name => :submit_id},
                {:name => :captcha_id},
                {:name => :urid}, # ?
                {:name => :basic_authorization},
                {:name => :method},
                {:name => :action, :encoding => :hex},
                {:name => :group_id},
                {:name => :deleted},
                {:name => :attach_key},
                {:name => :attach_present},
                {:name => :individual_share},
                {:name => :unknown1}
            ]
        end

        # 'EQDN' chunk contains information about equivalent domains
        def parse_chunk_EQDN stream
            parse_itemized_chunk stream, [
                {:name => :id},
                {:name => :domain, :encoding => :hex}
            ]
        end
    end
end
