require 'rake/testtask'

task :default => :test

Rake::TestTask.new :test do |task|
    task.test_files = FileList['test/test_*.rb']
    task.libs << 'lib'
end
