require "spec_helper"

describe LastPass::Fetcher do
    before :all do
        @username = "username"
        @password = "password"
        @key_iteration_count = 5000

        @session_id = "53ru,Hb713QnEVM5zWZ16jMvxS0"
        @session = LastPass::Session.new @session_id, @key_iteration_count

        @blob = "TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5"
    end

    describe ".request_iteration_count" do
        it "makes a POST request" do
            expect(web_client = double("web_client")).to receive(:post)
                .with("https://lastpass.com/iterations.php", query: {email: @username})
                .and_return(http_ok(@key_iteration_count.to_s))

            LastPass::Fetcher.request_iteration_count @username, web_client
        end

        it "returns key iteration count" do
            expect(
                LastPass::Fetcher.request_iteration_count @username,
                                                          double("web_client", post: http_ok(@key_iteration_count.to_s))
            ).to eq @key_iteration_count
        end

        it "raises an exception on HTTP error" do
            expect {
                LastPass::Fetcher.request_iteration_count @username,
                                                          double("web_client", post: http_error)
            }.to raise_error("Failed to request iterations")
        end
    end

    describe ".request_login" do
        it "makes a POST request" do
            expect(web_client = double("web_client")).to receive(:post)
                .with("https://lastpass.com/login.php", format: :xml, body: anything)
                .and_return(http_ok("ok" => {"sessionid" => @session_id}))

            LastPass::Fetcher.request_login @username, @password, @key_iteration_count, web_client
        end

        it "returns a session" do
            expect(web_client = double("web_client")).to receive(:post)
                .with("https://lastpass.com/login.php", format: :xml, body: anything)
                .and_return(http_ok("ok" => {"sessionid" => @session_id}))

            expect(
                LastPass::Fetcher.request_login @username, @password, @key_iteration_count, web_client
            ).to satisfy { |s| s.id == @session_id && s.key_iteration_count == @key_iteration_count }
        end
    end

    describe ".fetch" do
        it "makes a GET request" do
            expect(web_client = double("web_client")).to receive(:get)
                .with("https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0",
                      format: :plain,
                      cookies: {"PHPSESSID" => @session_id})
                .and_return(http_ok(@blob))

            LastPass::Fetcher.fetch @session, web_client
        end

        it "returns a blob" do
            expect(
                LastPass::Fetcher.fetch @session, double("web_client", get: http_ok(@blob))
            ).to eq @blob
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
end
