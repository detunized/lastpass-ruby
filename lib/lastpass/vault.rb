# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    class Vault
        attr_reader :accounts

        # Fetches a blob from the server and creates a vault
        def self.open_remote username, password
            open Vault.fetch_blob(username, password), username, password
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
        def self.fetch_blob username, password
            Fetcher.fetch Fetcher.login username, password
        end

        def initialize blob, encryption_key
            chunks = Parser.extract_chunks blob
            @accounts = (chunks["ACCT"] || []).map { |i| Parser.parse_account i, encryption_key }
        end

        # Do it via static constructor methods.
        private_class_method :new
    end
end
