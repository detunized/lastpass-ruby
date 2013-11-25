# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "lastpass/fetcher"
require "lastpass/parser"

module LastPass
    class Vault
        attr_reader :accounts

        def initialize blob
            chunks = Parser.extract_chunks blob
            @accounts = (chunks["ACCT"] || []).map { |i| Parser.parse_account i }
        end
    end
end
