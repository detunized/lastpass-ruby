require 'base64'
require "lastpass"

class String
    def decode64
        Base64.decode64 self
    end
end
