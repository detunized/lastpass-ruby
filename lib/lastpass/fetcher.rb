require 'pbkdf2'
require 'httparty'

module LastPass
    class Fetcher
        class << self
            def fetch(username, password, iterations = 1)
                fetcher = Fetcher.new username, password, iterations
                fetcher.send :fetch # To avoid exposing fetch

                fetcher
            end

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

        private

        def initialize username, password, iterations = 1
            @username = username
            @password = password
            @iterations = iterations
        end

        def fetch
            login
        end

        def login
            @key = Fetcher.make_key @username, @password, @iterations

            options = {
                'method' => 'mobile',
                'web' => 1,
                'xml' => 1,
                'username' => @username,
                'hash' => Fetcher.make_hash(@username, @password, @iterations),
                'iterations' => @iterations
            }

            response = HTTParty.post 'https://lastpass.com/login.php', {
                :output => 'xml',
                :query => options,
                :body => options
            }
        end
    end
end
