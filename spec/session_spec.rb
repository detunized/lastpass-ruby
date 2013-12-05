# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Session do
    let(:id) { "53ru,Hb713QnEVM5zWZ16jMvxS0" }
    let(:key_iteration_count) { 5000 }

    subject { LastPass::Session.new id, key_iteration_count }

    its(:id) { should eq id }
    its(:key_iteration_count) { should eq key_iteration_count }
end
