Gem::Specification.new do |s|
  s.name = 'ewelink'
  s.version = File.read("#{File.dirname(__FILE__)}/VERSION").strip
  s.platform = Gem::Platform::RUBY
  s.author = 'Alexis Toulotte'
  s.email = 'al@alweb.org'
  s.homepage = 'https://github.com/alexistoulotte/ewelink'
  s.summary = 'Manage eWeLink devices'
  s.description = 'Manage eWeLink smart home devices'
  s.license = 'MIT'

  s.files = %x(git ls-files | grep -vE '^(spec/|test/|\\.|Gemfile|Rakefile)').split("\n")
  s.executables = %x(git ls-files -- bin/*).split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.required_ruby_version = '>= 2.0.0'

  s.add_dependency 'activesupport', '>= 6.0.0', '< 7.0.0'
  s.add_dependency 'faye-websocket', '>= 0.11.0', '< 0.12.0'
  s.add_dependency 'httparty', '>= 0.18.0', '< 0.19.0'
  s.add_dependency 'thread', '>= 0.2.0', '< 0.3.0'

  s.add_development_dependency 'byebug', '>= 11.0.0', '< 12.0.0'
  s.add_development_dependency 'rake', '>= 13.0.0', '< 14.0.0'
  s.add_development_dependency 'rubocop', '>= 1.25.0', '< 2.0.0'
end
