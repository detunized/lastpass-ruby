# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Account do
    let(:id) { "id" }
    let(:name) { "name" }
    let(:username) { "username" }
    let(:password) { "password" }
    let(:url) { "url" }
    let(:group) { "group" }

    subject { LastPass::Account.new id, name, username, password, url, group }

    its(:id) { should eq id }
    its(:name) { should eq name }
    its(:username) { should eq username }
    its(:password) { should eq password }
    its(:url) { should eq url }
    its(:group) { should eq group }
end
