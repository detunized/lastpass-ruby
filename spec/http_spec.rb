# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::HTTP do
    let(:http) { LastPass::HTTP }

    describe "#http_proxy" do
        let(:url) { "https://proxy.example.com" }
        let(:port) { 12345 }
        let(:username) { "username" }
        let(:password) { "password" }

        it "sets the proxy options" do
            http.http_proxy url, port, username, password

            options = http.instance_variable_get :@default_options
            expect(options[:http_proxyaddr]).to eq url
            expect(options[:http_proxyport]).to eq port
            expect(options[:http_proxyuser]).to eq username
            expect(options[:http_proxypass]).to eq password
        end
    end
end
