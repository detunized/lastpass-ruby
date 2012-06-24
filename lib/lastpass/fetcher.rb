require 'pbkdf2'
require 'httparty'

module LastPass
    class Fetcher
        class << self
            def fetch username, password, iterations = 1
                fetcher = Fetcher.new username, password, iterations
                fetcher.send :fetch # To avoid exposing fetch

                fetcher
            end

            def make_key username, password, iterations = 1
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

            def make_hash username, password, iterations = 1
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

        def initialize username, password, iterations
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

            handle_response HTTParty.post 'https://lastpass.com/login.php', {
                :output => 'xml',
                :query => options,
                :body => options
            }
        end

        def handle_response response
            if !Net::HTTPOK === response.response
                raise RuntimeError, "Failed to login: '#{response}'"
            end

            parsed_response = response.parsed_response
            if !Hash === parsed_response
                raise RuntimeError, "Failed to login, cannot parse the response: '#{response}'"
            end

            if Hash === parsed_response['ok'] && (session_id = parsed_response['ok']['sessionid'])
                @session_id = session_id
            elsif Hash === parsed_response['response'] && Hash === parsed_response['response']['error']
                if iterations = parsed_response['response']['error']['iterations']
                    @iterations = iterations.to_i
                    login
                elsif message = parsed_response['response']['error']['message']
                    raise RuntimeError, "Failed to login, LastPass says '#{message}'"
                elsif
                    raise RuntimeError, 'Failed to login, LastPass responded with an unknown error'
                end
            else
                raise RuntimeError, 'Failed to login, the reason is unknown'
            end
        end
    end
end
