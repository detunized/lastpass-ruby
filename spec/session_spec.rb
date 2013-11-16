# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Session do
    before :all do
        @id = "53ru,Hb713QnEVM5zWZ16jMvxS0"
        @key_iteration_count = 5000
        @session = LastPass::Session.new @id, @key_iteration_count
    end

    it "#id returns the correct value" do
        @session.id.should == @id
    end

    it "#key_iteration_count returns the correct value" do
        @session.key_iteration_count.should == @key_iteration_count
    end
end
