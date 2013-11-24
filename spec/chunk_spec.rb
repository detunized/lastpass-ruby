# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Chunk do
    let(:id) { "IDID" }
    let(:payload) { "Payload" }

    subject { LastPass::Chunk.new id, payload }

    its(:id) { should eq id }
    its(:payload) { should eq payload }
end
