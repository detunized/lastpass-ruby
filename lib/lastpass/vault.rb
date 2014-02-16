# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    class Vault
        attr_reader :accounts

        # Fetches a blob from the server and creates a vault
        def self.open_remote username, password, multifactor_password = nil
            open Vault.fetch_blob(username, password, multifactor_password), username, password
        end

        # Creates a vault from a locally stored blob
        def self.open_local blob_filename, username, password
            # TODO: read the blob here
        end

        # Creates a vault from a blob object
        def self.open blob, username, password
            new blob, blob.encryption_key(username, password)
        end

        # Just fetches the blob, could be used to store it locally
        def self.fetch_blob username, password, multifactor_password = nil
            Fetcher.fetch Fetcher.login username, password, multifactor_password
        end

        # This more of an internal method, use one of the static constructors instead
        def initialize blob, encryption_key
            @accounts = []

            key = encryption_key
            rsa_private_key = nil

            Parser.extract_chunks(blob).each do |i|
                case i.id
                when "ACCT"
                    @accounts.push Parser.parse_ACCT i, key
                when "PRIK"
                    rsa_private_key = Parser.parse_PRIK i, encryption_key
                when "SHAR"
                    # After SHAR chunk all the folliwing accounts are enrypted with a new key
                    key = Parser.parse_SHAR(i, encryption_key, rsa_private_key)[:encryption_key]
                end
            end
        end
    end
end
