# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Session do
    let(:id) { "53ru,Hb713QnEVM5zWZ16jMvxS0" }
    let(:key_iteration_count) { 5000 }
    let(:session) { LastPass::Session.new id, key_iteration_count }

    it "#id returns the correct value" do
        expect(session.id).to eq id
    end

    it "#key_iteration_count returns the correct value" do
        expect(session.key_iteration_count).to eq key_iteration_count
    end
end
