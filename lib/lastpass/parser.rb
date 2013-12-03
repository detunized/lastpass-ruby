# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "base64"
require "openssl"
require "stringio"

require_relative "chunk"

module LastPass
    class Parser
        def self.extract_chunks blob
            chunks = Hash.new { |hash, key| hash[key] = [] }

            StringIO.open blob.bytes do |stream|
                while !stream.eof?
                    chunk = read_chunk stream
                    chunks[chunk.id] << chunk
                end
            end

            chunks
        end

        def self.parse_account chunk, encryption_key
            StringIO.open chunk.payload do |io|
                id = read_item io
                name = read_item io
                group = read_item io
                url = decode_hex read_item io
                3.times { skip_item io }
                username = read_item io
                password = read_item io

                Account.new id, name, username, password, url, group
            end
        end

        def self.read_chunk stream
            # LastPass blob chunk is made up of 4-byte ID,
            # big endian 4-byte size and payload of that size.
            #
            # Example:
            #   0000: 'IDID'
            #   0004: 4
            #   0008: 0xDE 0xAD 0xBE 0xEF
            #   000C: --- Next chunk ---

            Chunk.new read_id(stream), read_payload(stream, read_size(stream))
        end

        def self.read_item stream
            # An item in an itemized chunk is made up of the
            # big endian size and the payload of that size.
            #
            # Example:
            #   0000: 4
            #   0004: 0xDE 0xAD 0xBE 0xEF
            #   0008: --- Next item ---

            read_payload stream, read_size(stream)
        end

        def self.skip_item stream
            read_item stream
        end

        def self.read_id stream
            stream.read 4
        end

        def self.read_size stream
            read_uint32 stream
        end

        def self.read_payload stream, size
            stream.read size
        end

        def self.read_uint32 stream
            stream.read(4).unpack("N").first
        end

        def self.decode_hex data
            raise ArgumentError, "Input length must be multple of 2" unless data.size % 2 == 0
            raise ArgumentError, "Input contains invalid characters" unless data =~ /^[0-9a-f]*$/i

            data.scan(/../).map { |i| i.to_i 16 }.pack "c*"
        end

        def self.decode_base64 data
            # TODO: Check for input validity
            Base64.decode64 data
        end

        # Guesses AES encoding/cipher from the length of the data.
        def self.decode_aes256_auto data, encryption_key
            length = data.length
            length16 = length % 16
            length64 = length % 64

            if length == 0
                ""
            elsif length16 == 0
                decode_aes256_ecb_plain data, encryption_key
            elsif length64 == 0 || length64 == 24 || length64 == 44
                decode_aes256_ecb_base64 data, encryption_key
            elsif length16 == 1
                decode_aes256_cbc_plain data, encryption_key
            elsif length64 == 6 || length64 == 26 || length64 == 50
                decode_aes256_cbc_base64 data, encryption_key
            else
                raise RuntimeError, "'#{data.inspect}' doesn't seem to be AES-256 encrypted"
            end
        end

        def self.decode_aes256_ecb_plain data, encryption_key
            if data.empty?
                ""
            else
                decode_aes256 :ecb, "", data, encryption_key
            end
        end

        def self.decode_aes256_ecb_base64 data, encryption_key
            decode_aes256_ecb_plain decode_base64(data), encryption_key
        end

        # LastPass AES-256/CBC encryted string starts with '!'.
        # Next 16 bytes are the IV for the cipher.
        # And the rest is the encrypted payload.
        def self.decode_aes256_cbc_plain data, encryption_key
            if data.empty?
                ""
            else
                # TODO: Check for input validity!
                decode_aes256 :cbc, data[1, 16], data[17..-1], encryption_key
            end
        end

        # LastPass AES-256/CBC/base64 encryted string starts with '!'.
        # Next 24 bytes are the base64 encoded IV for the cipher.
        # Then comes the '|'.
        # And the rest is the base64 encoded encrypted payload.
        def self.decode_aes256_cbc_base64 data, encryption_key
            if data.empty?
                ""
            else
                # TODO: Check for input validity!
                decode_aes256 :cbc, decode_base64(data[1, 24]), decode_base64(data[26..-1]), encryption_key
            end
        end

        # Allowed ciphers are :ecb and :cbc.
        # If for :ecb iv is not used and should be set to ''.
        def self.decode_aes256 cipher, iv, data, encryption_key
            aes = OpenSSL::Cipher::Cipher.new "aes-256-#{cipher}"
            aes.decrypt
            aes.key = encryption_key
            aes.iv = iv
            aes.update(data) + aes.final
        end
    end
end
