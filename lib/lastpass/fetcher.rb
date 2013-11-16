require 'pbkdf2'
require 'httparty'

require_relative 'session'

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

        # Binary blob received from LastPass, which should handed off to the parser
        attr_reader :blob

        # The encryption key, which also have to be sent to the parser for it to be able
        # to decrypt the account data.
        attr_reader :encryption_key

        # Number of iterations used in the key generation process.  It could be stored and
        # used later to save one extra request during the fetch process.  Normally, when
        # an incorrect number is given, the LastPass server responds with the correct one
        # and the key/hash pair is regenerated and sent back in the follow-up request.
        # You can also see this number in your account settings under General ->
        # Password Iterations (PBKDF2).  Set it to something big, like 500 or even bigger.
        attr_reader :iterations

        private

        def initialize username, password, iterations
            @username = username
            @password = password
            @iterations = iterations
        end

        def fetch
            @blob = fetch_blob login
        end

        # Returns the created session id
        def login
            @encryption_key = Fetcher.make_key @username, @password, @iterations

            options = {
                'method' => 'mobile',
                'web' => 1,
                'xml' => 1,
                'username' => @username,
                'hash' => Fetcher.make_hash(@username, @password, @iterations),
                'iterations' => @iterations
            }

            handle_login_response HTTParty.post 'https://lastpass.com/login.php', {
                :output => 'xml',
                :query => options,
                :body => options
            }
        end

        # Returns the created session id
        def handle_login_response response
            if !Net::HTTPOK === response.response
                raise RuntimeError, "Failed to login: '#{response}'"
            end

            parsed_response = response.parsed_response
            if !Hash === parsed_response
                raise RuntimeError, "Failed to login, cannot parse the response: '#{response}'"
            end

            if Hash === parsed_response['ok'] && (session_id = parsed_response['ok']['sessionid'])
                session_id
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

        # Returns the blob which should be passed by the client to the parser
        def fetch_blob session_id
            response = HTTParty.get(
                "https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0",
                :output => :plain,
                :cookies => {'PHPSESSID' => URI.encode(session_id)}
            )

            if Net::HTTPOK === response.response
                response.parsed_response
            else
                raise RuntimeError, "Failed to fetch data from LastPass"
            end
        end
    end
end
