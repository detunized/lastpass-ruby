# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "base64"
require "lastpass"

class String
    def decode64
        Base64.decode64 self
    end
end

module LastPass
    class Session
        def == other
            id == other.id && key_iteration_count == other.key_iteration_count
        end
    end

    class Blob
        def == other
            bytes == other.bytes && key_iteration_count == other.key_iteration_count
        end
    end
end
