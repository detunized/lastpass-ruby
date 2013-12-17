# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    class Fetcher
        def self.login username, password, multifactor_password = nil
            key_iteration_count = request_iteration_count username
            request_login username, password, key_iteration_count, multifactor_password
        end

        def self.fetch session, web_client = HTTParty
            response = web_client.get "https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0",
                                      format: :plain,
                                      cookies: {"PHPSESSID" => URI.encode(session.id)}

            raise NetworkError unless response.response.is_a? Net::HTTPOK

            Blob.new decode_blob(response.parsed_response), session.key_iteration_count
        end

        def self.request_iteration_count username, web_client = HTTParty
            response = web_client.post "https://lastpass.com/iterations.php",
                                       query: {email: username}

            raise NetworkError unless response.response.is_a? Net::HTTPOK

            begin
                count = Integer response.parsed_response
            rescue ArgumentError
                raise InvalidResponseError, "Key iteration count is invalid"
            end

            raise InvalidResponseError, "Key iteration count is not positive" unless count > 0

            count
        end

        def self.request_login username,
                               password,
                               key_iteration_count,
                               multifactor_password = nil,
                               web_client = HTTParty

            body = {
                method: "mobile",
                web: 1,
                xml: 1,
                username: username,
                hash: make_hash(username, password, key_iteration_count),
                iterations: key_iteration_count
            }

            body[:otp] = multifactor_password if multifactor_password

            response = web_client.post "https://lastpass.com/login.php",
                                       format: :xml,
                                       body: body

            raise NetworkError unless response.response.is_a? Net::HTTPOK

            parsed_response = response.parsed_response
            raise InvalidResponseError unless parsed_response.is_a? Hash

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
            error = (parsed_response["response"] || {})["error"]
            return UnknownResponseSchemaError unless error.is_a? Hash

            exceptions = {
                "unknownemail" => LastPassUnknownUsernameError,
                "unknownpassword" => LastPassInvalidPasswordError,
            }

            cause = error["cause"]
            message = error["message"]

            if cause
                (exceptions[cause] || LastPassUnknownError).new message || cause
            else
                InvalidResponseError.new message
            end
        end

        def self.decode_blob blob
            # TODO: Check for invalid base64
            Base64.decode64 blob
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

        # Can't instantiate Fetcher
        private_class_method :new
    end
end
