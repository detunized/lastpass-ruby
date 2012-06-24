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

            def make_hash(username, password, iterations = 1)
                if iterations == 1
                    Digest::SHA256.hexdigest(Digest.hexencode(make_key(username, password, 1)) + password)
                else
                    PBKDF2.new(
                        :password => make_key(username, password, iterations),
                        :salt => password,
                        :iterations => 1,
                        :key_length => 32
                    ).hex_string
                end
            end
        end
    end
end
