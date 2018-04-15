# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Session do
    let(:id) { "53ru,Hb713QnEVM5zWZ16jMvxS0" }
    let(:key_iteration_count) { 5000 }
    let(:encrypted_private_key) { "DEADBEEF" }

    subject { LastPass::Session.new id, key_iteration_count, encrypted_private_key }

    its(:id) { should eq id }
    its(:key_iteration_count) { should eq key_iteration_count }
    its(:encrypted_private_key) { should eq encrypted_private_key }
end
