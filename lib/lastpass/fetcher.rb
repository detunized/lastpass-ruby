# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "pbkdf2"
require "httparty"

require_relative "session"
require_relative "exceptions"

module LastPass
    class Fetcher
        def self.login username, password
            key_iteration_count = request_iteration_count username
            request_login username, password, key_iteration_count
        end

        def self.fetch session, web_client = HTTParty
            response = web_client.get "https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0",
                                      format: :plain,
                                      cookies: {"PHPSESSID" => URI.encode(session.id)}

            raise NetworkError unless response.response.is_a? Net::HTTPOK
            response.parsed_response
        end

        def self.request_iteration_count username, web_client = HTTParty
            response = web_client.post "https://lastpass.com/iterations.php",
                                       query: {email: username}

            raise NetworkError unless response.response.is_a? Net::HTTPOK
            response.parsed_response.to_i
        end

        def self.request_login username, password, key_iteration_count, web_client = HTTParty
            response = web_client.post "https://lastpass.com/login.php",
                                       format: :xml,
                                       body: {
                                           method: "mobile",
                                           web: 1,
                                           xml: 1,
                                           username: username,
                                           hash: make_hash(username, password, key_iteration_count),
                                           iterations: key_iteration_count
                                       }

            raise NetworkError unless response.response.is_a? Net::HTTPOK

            parsed_response = response.parsed_response
            raise "Invalid response" unless parsed_response.is_a? Hash

            create_session parsed_response, key_iteration_count or
                raise login_error parsed_response
        end

        def self.create_session parsed_response, key_iteration_count
            ok = parsed_response["ok"]
            if ok.is_a? Hash
                session_id = ok["sessionid"]
                if session_id.is_a? String
                    return Session.new session_id, key_iteration_count
                end
            end

            nil
        end

        def self.login_error parsed_response
            "Login failed"
        end

        def self.make_key username, password, key_iteration_count
            if key_iteration_count == 1
                Digest::SHA256.digest username + password
            else
                PBKDF2
                    .new(password: password,
                         salt: username,
                         iterations: key_iteration_count,
                         key_length: 32)
                    .bin_string
                    .force_encoding "BINARY"
            end
        end

        def self.make_hash username, password, key_iteration_count
            if key_iteration_count == 1
                Digest::SHA256.hexdigest Digest.hexencode(make_key(username, password, 1)) + password
            else
                PBKDF2
                    .new(password: make_key(username, password, key_iteration_count),
                         salt: password,
                         iterations: 1,
                         key_length: 32)
                    .hex_string
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

        # Can't instantiate Fetcher
        private_class_method :new

        # Returns the created session id
        def handle_login_response response
            if !Net::HTTPOK === response.response
                raise RuntimeError, "Failed to login: '#{response}'"
            end

            parsed_response = response.parsed_response
            if !Hash === parsed_response
                raise RuntimeError, "Failed to login, cannot parse the response: '#{response}'"
            end

            if Hash === parsed_response["ok"] && (session_id = parsed_response["ok"]["sessionid"])
                session_id
            elsif Hash === parsed_response["response"] && Hash === parsed_response["response"]["error"]
                if iterations = parsed_response["response"]["error"]["iterations"]
                    @iterations = iterations.to_i
                    login
                elsif message = parsed_response["response"]["error"]["message"]
                    raise RuntimeError, "Failed to login, LastPass says '#{message}'"
                elsif
                    raise RuntimeError, "Failed to login, LastPass responded with an unknown error"
                end
            else
                raise RuntimeError, "Failed to login, the reason is unknown"
            end
        end
    end
end
