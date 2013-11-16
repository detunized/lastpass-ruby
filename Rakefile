# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require 'rake/testtask'

task :default => :test

Rake::TestTask.new :test

task :example do
    ruby "-Ilib", "example/example.rb"
end
