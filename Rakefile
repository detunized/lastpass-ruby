# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "rspec/core/rake_task"

task :default => :spec

# Spec
RSpec::Core::RakeTask.new :spec do |task|
    task.rspec_opts = "--format nested --color"
end

# Example
task :example do
    ruby "-Ilib", "example/example.rb"
end
