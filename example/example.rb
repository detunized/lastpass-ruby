# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "lastpass"
require "yaml"

credentials = YAML.load_file File.join File.dirname(__FILE__), "credentials.yaml"

session = LastPass::Fetcher.login credentials["username"], credentials["password"]
blob = LastPass::Fetcher.fetch session
