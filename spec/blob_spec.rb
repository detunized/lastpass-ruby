# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "spec_helper"

describe LastPass::Blob do
    let(:bytes) { "TFBBVgAAAAMxMjJQUkVNAAAACjE0MTQ5".decode64 }
    let(:key_iteration_count) { 5000 }

    subject { LastPass::Blob.new bytes, key_iteration_count }

    its(:bytes) { should eq bytes }
    its(:key_iteration_count) { should eq key_iteration_count }
end
