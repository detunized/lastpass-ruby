# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "lastpass/fetcher"
require "lastpass/parser"

module LastPass
    class Vault
        def initialize blob
            Parser.extract_chunks blob
        end
    end
end
