# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Fetcher do
    let(:username) { "username" }
    let(:password) { "password" }
    let(:key_iteration_count) { 5000 }

    let(:hash) { "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256" }
    let(:session_id) { "53ru,Hb713QnEVM5zWZ16jMvxS0" }
    let(:escaped_session_id) { "53ru%2CHb713QnEVM5zWZ16jMvxS0" }
    let(:session) { LastPass::Session.new session_id, key_iteration_count, "DEADBEEF" }

    let(:blob_response) { "TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5" }
    let(:blob_bytes) { blob_response.decode64 }
    let(:blob) { LastPass::Blob.new blob_bytes, key_iteration_count, "DEADBEEF" }

    let(:login_post_data) { {method: "cli",
                             xml: 2,
                             username: username,
                             hash: hash,
                             iterations: key_iteration_count,
                             includeprivatekeyenc: 1} }

    let(:device_id) { "492378378052455" }
    let(:login_post_data_with_device_id) { login_post_data.merge({imei: device_id}) }

    let(:google_authenticator_code) { "123456" }
    let(:yubikey_password) { "emdbwzemyisymdnevznyqhqnklaqheaxszzvtnxjrmkb" }

    let(:login_post_data_with_google_authenticator_code) { login_post_data.merge({otp: google_authenticator_code}) }
    let(:login_post_data_with_yubikey_password) { login_post_data.merge({otp: yubikey_password}) }

    describe ".logout" do
        it "makes a GET request" do
            web_client = double "web_client"
            expect(web_client).to receive(:get)
                .with("https://lastpass.com/logout.php?method=cli&noredirect=1", cookies: {"PHPSESSID" => escaped_session_id})
                .and_return(http_ok "")
            LastPass::Fetcher.logout session, web_client
        end

        it "raises an exception on HTTP error" do
            expect {
                LastPass::Fetcher.logout session, double("web_client", get: http_error)
            }.to raise_error LastPass::NetworkError
        end
    end

    describe ".request_iteration_count" do
        it "makes a POST request" do
            expect(web_client = double("web_client")).to receive(:post)
                .with("https://lastpass.com/iterations.php", body: {email: username})
                .and_return(http_ok(key_iteration_count.to_s))

            LastPass::Fetcher.request_iteration_count username, web_client
        end

        it "returns key iteration count" do
            expect(
                LastPass::Fetcher.request_iteration_count username,
                                                          double("web_client", post: http_ok(key_iteration_count.to_s))
            ).to eq key_iteration_count
        end

        it "raises an exception on HTTP error" do
            expect {
                LastPass::Fetcher.request_iteration_count username,
                                                          double("web_client", post: http_error)
            }.to raise_error LastPass::NetworkError
        end

        it "raises an exception on invalid key iteration count" do
            expect {
                LastPass::Fetcher.request_iteration_count username,
                                                          double("web_client", post: http_ok("not a number"))
            }.to raise_error LastPass::InvalidResponseError, "Key iteration count is invalid"
        end

        it "raises an exception on zero key iteration count" do
            expect {
                LastPass::Fetcher.request_iteration_count username,
                                                          double("web_client", post: http_ok("0"))
            }.to raise_error LastPass::InvalidResponseError, "Key iteration count is not positive"
        end

        it "raises an exception on negative key iteration count" do
            expect {
                LastPass::Fetcher.request_iteration_count username,
                                                          double("web_client", post: http_ok("-1"))
            }.to raise_error LastPass::InvalidResponseError, "Key iteration count is not positive"
        end
    end

    describe ".request_login" do
        def verify_post_request multifactor_password, device_id, post_data
            web_client = double("web_client")
            expect(web_client).to receive(:post)
                .with("https://lastpass.com/login.php", format: :xml, body: post_data)
                .and_return(http_ok("response" => {"ok" => {"sessionid" => session_id, "privatekeyenc" => "DEADBEEF"}}))

            LastPass::Fetcher.request_login username,
                                            password,
                                            key_iteration_count,
                                            multifactor_password,
                                            device_id,
                                            web_client
        end

        it "makes a POST request" do
            verify_post_request nil, nil, login_post_data
        end

        it "makes a POST request with device id" do
            verify_post_request nil, device_id, login_post_data_with_device_id
        end

        it "makes a POST request with Google Authenticator code" do
            verify_post_request google_authenticator_code, nil, login_post_data_with_google_authenticator_code
        end

        it "makes a POST request with Yubikey password" do
            verify_post_request yubikey_password, nil, login_post_data_with_yubikey_password
        end

        it "returns a session" do
            expect(request_login_with_xml "<response><ok sessionid='#{session_id}' /></response>").to eq session
        end

        it "raises an exception on HTTP error" do
            expect { request_login_with_error }.to raise_error LastPass::NetworkError
        end

        it "raises an exception when response is not a hash" do
            expect { request_login_with_ok "not a hash" }.to raise_error LastPass::InvalidResponseError
        end

        it "raises an exception on unknown response schema" do
            expect { request_login_with_xml "<unknown />" }.to raise_error LastPass::UnknownResponseSchemaError
        end

        it "raises an exception on unknown response schema" do
            expect { request_login_with_xml "<response />" }.to raise_error LastPass::UnknownResponseSchemaError
        end

        it "raises an exception on unknown response schema" do
            expect { request_login_with_xml "<response><error /></response>" }
                .to raise_error LastPass::UnknownResponseSchemaError
        end

        it "raises an exception on unknown username" do
            message = "Unknown email address."
            expect { request_login_with_lastpass_error "unknownemail", message }
                .to raise_error LastPass::LastPassUnknownUsernameError, message
        end

        it "raises an exception on invalid password" do
            message = "Invalid password!"
            expect { request_login_with_lastpass_error "unknownpassword", message }
                .to raise_error LastPass::LastPassInvalidPasswordError, message
        end

        it "raises an exception on missing Google Authenticator code" do
            message = "Google Authenticator authentication required! " +
                      "Upgrade your browser extension so you can enter it."
            expect { request_login_with_lastpass_error "googleauthrequired", message }
                .to raise_error LastPass::LastPassIncorrectGoogleAuthenticatorCodeError, message
        end

        it "raises an exception on incorrect Google Authenticator code" do
            message = "Google Authenticator authentication failed!"
            expect { request_login_with_lastpass_error "googleauthfailed", message }
                .to raise_error LastPass::LastPassIncorrectGoogleAuthenticatorCodeError, message
        end

        it "raises an exception on missing/incorrect Yubikey password" do
            message = "Your account settings have restricted you from logging in " +
                      "from mobile devices that do not support YubiKey authentication."
            expect { request_login_with_lastpass_error "otprequired", message }
                .to raise_error LastPass::LastPassIncorrectYubikeyPasswordError, message
        end

        it "raises an exception on unknown LastPass error with a message" do
            message = "Unknow error message"
            expect { request_login_with_lastpass_error "Unknown cause", message }
                .to raise_error LastPass::LastPassUnknownError, message
        end

        it "raises an exception on unknown LastPass error without a message" do
            cause = "Unknown casue"
            expect { request_login_with_lastpass_error cause }
                .to raise_error LastPass::LastPassUnknownError, cause
        end
    end

    describe ".fetch" do
        it "makes a GET request" do
            expect(web_client = double("web_client")).to receive(:get)
                .with("https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=cli",
                      format: :plain,
                      cookies: {"PHPSESSID" => escaped_session_id})
                .and_return(http_ok(blob_response))

            LastPass::Fetcher.fetch session, web_client
        end

        it "returns a blob" do
            expect(LastPass::Fetcher.fetch session, double("web_client", get: http_ok(blob_response)))
                .to eq blob
        end

        it "raises an exception on HTTP error" do
            expect {
                LastPass::Fetcher.fetch session, double("web_client", get: http_error)
            }   .to raise_error LastPass::NetworkError
        end
    end

    describe ".make_key" do
        it "generates correct keys" do
            def key iterations
                LastPass::Fetcher.make_key "postlass@gmail.com", "pl1234567890", iterations
            end

            expect(key 1).to eq "C/Bh2SGWxI8JDu54DbbpV8J9wa6pKbesIb9MAXkeF3Y=".decode64
            expect(key 5).to eq "pE9goazSCRqnWwcixWM4NHJjWMvB5T15dMhe6ug1pZg=".decode64
            expect(key 10).to eq "n9S0SyJdrMegeBHtkxUx8Lzc7wI6aGl+y3/udGmVey8=".decode64
            expect(key 50).to eq "GwI8/kNy1NjIfe3Z0VAZfF78938UVuCi6xAL3MJBux0=".decode64
            expect(key 100).to eq "piGdSULeHMWiBS3QJNM46M5PIYwQXA6cNS10pLB3Xf8=".decode64
            expect(key 500).to eq "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".decode64
            expect(key 1000).to eq "z7CdwlIkbu0XvcB7oQIpnlqwNGemdrGTBmDKnL9taPg=".decode64
        end
    end

    describe ".make_hash" do
        it "generates correct hashes" do
            def hash iterations
                LastPass::Fetcher.make_hash "postlass@gmail.com", "pl1234567890", iterations
            end

            expect(hash 1).to eq "a1943cfbb75e37b129bbf78b9baeab4ae6dd08225776397f66b8e0c7a913a055"
            expect(hash 5).to eq "a95849e029a7791cfc4503eed9ec96ab8675c4a7c4e82b00553ddd179b3d8445"
            expect(hash 10).to eq "0da0b44f5e6b7306f14e92de6d629446370d05afeb1dc07cfcbe25f169170c16"
            expect(hash 50).to eq "1d5bc0d636da4ad469cefe56c42c2ff71589facb9c83f08fcf7711a7891cc159"
            expect(hash 100).to eq "82fc12024acb618878ba231a9948c49c6f46e30b5a09c11d87f6d3338babacb5"
            expect(hash 500).to eq "3139861ae962801b59fc41ff7eeb11f84ca56d810ab490f0d8c89d9d9ab07aa6"
            expect(hash 1000).to eq "03161354566c396fcd624a424164160e890e96b4b5fa6d942fc6377ab613513b"
        end
    end

    #
    # Helpers
    #

    private

    def mock_response type, code, body
        double response: type.new("1.1", code, ""),
               parsed_response: body
    end

    def http_ok body
        mock_response Net::HTTPOK, 200, body
    end

    def http_error body = ""
        mock_response Net::HTTPNotFound, 404, body
    end

    def xml text
        MultiXml.parse text
    end

    def lastpass_error cause, message
        if message
            %Q{<response><error cause="#{cause}" message="#{message}" /></response>}
        else
            %Q{<response><error cause="#{cause}" /></response>}
        end
    end

    def request_login_with_lastpass_error cause, message = nil
        request_login_with_xml lastpass_error cause, message
    end

    def request_login_with_xml text
        request_login_with_ok xml text
    end

    def request_login_with_ok response
        request_login_with_response http_ok response
    end

    def request_login_with_error
        request_login_with_response http_error
    end

    def request_login_with_response response
        LastPass::Fetcher.request_login username,
                                        password,
                                        key_iteration_count,
                                        nil,
                                        nil,
                                        double("web_client", post: response)
    end
end
