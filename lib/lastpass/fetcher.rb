require 'pbkdf2'

module LastPass
    class Fetcher
        class << self
            def make_key(username, password, iterations = 1)
                if iterations == 1
                    Digest::SHA256.digest username + password
                else
                    PBKDF2.new(
                        :password => password,
                        :salt => username,
                        :iterations => iterations,
                        :key_length => 32
                    ).bin_string.force_encoding 'BINARY'
                end
            end
        end
    end
end
