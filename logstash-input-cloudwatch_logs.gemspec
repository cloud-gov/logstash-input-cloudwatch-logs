# frozen_string_literal: true

Gem::Specification.new do |s|
  s.required_ruby_version = '= 3.1.4'

  s.name            = 'logstash-input-cloudwatch_logs'
  s.version         = '1.1.4'
  s.licenses        = ['Apache-2.0']
  s.summary         = 'Stream events from CloudWatch Logs.'
  s.description     = 'This gem is a logstash plugin required to be installed on top of the Logstash core pipeline'\
    ' using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program'
  s.homepage        = ''
  s.require_paths = ['lib']
  s.authors = 'Cloud-gov'
  # Files
  s.files = Dir[
    'lib/**/*',
    'spec/**/*',
    'vendor/**/*',
    '*.gemspec',
    '*.md',
    'CONTRIBUTORS',
    'Gemfile',
    'LICENSE',
    'NOTICE.TXT'
  ]

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { 'logstash_plugin' => 'true', 'logstash_group' => 'input' }

  # Gem dependencies
  s.add_runtime_dependency 'jar-dependencies', '= 0.4.1'
  s.add_runtime_dependency 'logstash-core-plugin-api', '>= 1.60', '<= 2.99'
  s.add_runtime_dependency 'logstash-integration-aws', '>= 7.1.0'
  s.add_runtime_dependency 'stud', '~> 0.0.22'

  s.add_development_dependency 'rubocop'
end
