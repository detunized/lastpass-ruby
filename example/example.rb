# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

# Run via top level rake file:
# $ rake example

require "lastpass"
require "yaml"

credentials = YAML.load_file File.join File.dirname(__FILE__), "credentials.yaml"

username = credentials["username"]
password = credentials["password"]

begin
    # First try without a multifactor password
    vault = LastPass::Vault.open_remote username, password
rescue LastPass::LastPassIncorrectGoogleAuthenticatorCodeError => e
    # Get the code
    puts "Enter Google Authenticator code:"
    code = gets.chomp

    # And now retry with the code
    vault = LastPass::Vault.open_remote username, password, code
end

vault.accounts.each_with_index do |i, index|
    puts "#{index + 1}: #{i.id} #{i.name} #{i.username} #{i.password} #{i.url} #{i.group}}"
end
