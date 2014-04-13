# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    class Parser
        # OpenSSL constant
        RSA_PKCS1_OAEP_PADDING = 4

        # Splits the blob into chucks grouped by kind.
        def self.extract_chunks blob
            chunks = []

            StringIO.open blob.bytes do |stream|
                while !stream.eof?
                    chunks.push read_chunk stream
                end
            end

            chunks
        end

        # Parses an account chunk, decrypts and creates an Account object.
        # May return nil when the chunk does not represent an account.
        # All secure notes are ACCTs but not all of them strore account
        # information.
        #
        # TODO: Make a test case that covers secure note account
        def self.parse_ACCT chunk, encryption_key
            StringIO.open chunk.payload do |io|
                id = read_item io
                name = decode_aes256_auto read_item(io), encryption_key
                group = decode_aes256_auto read_item(io), encryption_key
                url = decode_hex read_item io
                notes = decode_aes256_auto read_item(io), encryption_key
                2.times { skip_item io }
                username = decode_aes256_auto read_item(io), encryption_key
                password = decode_aes256_auto read_item(io), encryption_key
                2.times { skip_item io }
                secure_note = read_item io

                # Parse secure note
                if secure_note == "1"
                    17.times { skip_item io }
                    secure_note_type = read_item io

                    # Only "Server" secure note stores account information
                    if secure_note_type != "Server"
                        return nil
                    end

                    url, username, password = parse_secure_note_server notes
                end

                Account.new id, name, username, password, url, group
            end
        end

        # Parse PRIK chunk which contains private RSA key
        def self.parse_PRIK chunk, encryption_key
            decrypted = decode_aes256 "cbc",
                                      encryption_key[0, 16],
                                      decode_hex(chunk.payload),
                                      encryption_key

            /^LastPassPrivateKey<(?<hex_key>.*)>LastPassPrivateKey$/ =~ decrypted
            asn1_encoded_all = OpenSSL::ASN1.decode decode_hex hex_key
            asn1_encoded_key = OpenSSL::ASN1.decode asn1_encoded_all.value[2].value

            rsa_key = OpenSSL::PKey::RSA.new
            rsa_key.n = asn1_encoded_key.value[1].value
            rsa_key.e = asn1_encoded_key.value[2].value
            rsa_key.d = asn1_encoded_key.value[3].value
            rsa_key.p = asn1_encoded_key.value[4].value
            rsa_key.q = asn1_encoded_key.value[5].value
            rsa_key.dmp1 = asn1_encoded_key.value[6].value
            rsa_key.dmq1 = asn1_encoded_key.value[7].value
            rsa_key.iqmp = asn1_encoded_key.value[8].value

            rsa_key
        end

        # TODO: Fake some data and make a test
        def self.parse_SHAR chunk, encryption_key, rsa_key
            StringIO.open chunk.payload do |io|
                id = read_item io
                encrypted_key = decode_hex read_item io
                encrypted_name = read_item io
                2.times { skip_item io }
                key = read_item io

                # Shared folder encryption key might come already in pre-decrypted form,
                # where it's only AES encrypted with the regular encryption key.
                # When the key is blank, then there's a RSA encrypted key, which has to
                # be decrypted first before use.
                key = if key.empty?
                    decode_hex rsa_key.private_decrypt(encrypted_key, RSA_PKCS1_OAEP_PADDING)
                else
                    decode_hex decode_aes256_auto(key, encryption_key)
                end

                name = decode_aes256_auto encrypted_name, key

                # TODO: Return an object, not a hash
                {id: id, name: name, encryption_key: key}
            end
        end

        def self.parse_secure_note_server notes
            url = nil
            username = nil
            password = nil

            notes.split("\n").each do |i|
                key, value = i.split ":", 2
                case key
                when "Hostname"
                    url = value
                when "Username"
                    username = value
                when "Password"
                    password = value
                end
            end

            [url, username, password]
        end

        # Reads one chunk from a stream and creates a Chunk object with the data read.
        def self.read_chunk stream
            # LastPass blob chunk is made up of 4-byte ID,
            # big endian 4-byte size and payload of that size.
            #
            # Example:
            #   0000: "IDID"
            #   0004: 4
            #   0008: 0xDE 0xAD 0xBE 0xEF
            #   000C: --- Next chunk ---
            Chunk.new read_id(stream), read_payload(stream, read_size(stream))
        end

        # Reads an item from a stream and returns it as a string of bytes.
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

        # Skips an item in a stream.
        def self.skip_item stream
            read_item stream
        end

        # Reads a chunk ID from a stream.
        def self.read_id stream
            stream.read 4
        end

        # Reads a chunk or an item ID.
        def self.read_size stream
            read_uint32 stream
        end

        # Reads a payload of a given size from a stream.
        def self.read_payload stream, size
            stream.read size
        end

        # Reads an unsigned 32 bit integer from a stream.
        def self.read_uint32 stream
            stream.read(4).unpack("N").first
        end

        # Decodes a hex encoded string into raw bytes.
        def self.decode_hex data
            raise ArgumentError, "Input length must be multple of 2" unless data.size % 2 == 0
            raise ArgumentError, "Input contains invalid characters" unless data =~ /^[0-9a-f]*$/i

            data.scan(/../).map { |i| i.to_i 16 }.pack "c*"
        end

        # Decodes a base64 encoded string into raw bytes.
        def self.decode_base64 data
            # TODO: Check for input validity!
            Base64.decode64 data
        end

        # Guesses AES encoding/cipher from the length of the data.
        # Possible combinations are:
        #   - ciphers: AES-256 EBC, AES-256 CBC
        #   - encodings: plain, base64
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

        # Decrypts AES-256 ECB bytes.
        def self.decode_aes256_ecb_plain data, encryption_key
            if data.empty?
                ""
            else
                decode_aes256 :ecb, "", data, encryption_key
            end
        end

        # Decrypts base64 encoded AES-256 ECB bytes.
        def self.decode_aes256_ecb_base64 data, encryption_key
            decode_aes256_ecb_plain decode_base64(data), encryption_key
        end

        # Decrypts AES-256 CBC bytes.
        def self.decode_aes256_cbc_plain data, encryption_key
            if data.empty?
                ""
            else
                # LastPass AES-256/CBC encryted string starts with an "!".
                # Next 16 bytes are the IV for the cipher.
                # And the rest is the encrypted payload.

                # TODO: Check for input validity!
                decode_aes256 :cbc,
                              data[1, 16],
                              data[17..-1],
                              encryption_key
            end
        end

        # Decrypts base64 encoded AES-256 CBC bytes.
        def self.decode_aes256_cbc_base64 data, encryption_key
            if data.empty?
                ""
            else
                # LastPass AES-256/CBC/base64 encryted string starts with an "!".
                # Next 24 bytes are the base64 encoded IV for the cipher.
                # Then comes the "|".
                # And the rest is the base64 encoded encrypted payload.

                # TODO: Check for input validity!
                decode_aes256 :cbc,
                              decode_base64(data[1, 24]),
                              decode_base64(data[26..-1]),
                              encryption_key
            end
        end

        # Decrypt AES-256 bytes.
        # Allowed ciphers are: :ecb, :cbc.
        # If for :ecb iv is not used and should be set to "".
        def self.decode_aes256 cipher, iv, data, encryption_key
            aes = OpenSSL::Cipher::Cipher.new "aes-256-#{cipher}"
            aes.decrypt
            aes.key = encryption_key
            aes.iv = iv
            aes.update(data) + aes.final
        end
    end
end
