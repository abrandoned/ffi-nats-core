require "bundler/gem_tasks"
require "rake/testtask"

namespace :cnats do
  desc "build cnats"
  task :compile do
    load "ext/ffi/nats/core/Rakefile"
  end

  desc "checkout cnats source"
  task :checkout do
    puts ::File.directory?("vendor/cnats/build")
    unless ::File.directory?("vendor/cnats/build")
      sh "git submodule update --init"
    end
  end
end
Rake::Task["cnats:compile"].prerequisites.insert(0, "cnats:checkout")

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList['test/**/*_test.rb']
end
Rake::Task[:test].prerequisites << "cnats:compile"

task :default => :test
