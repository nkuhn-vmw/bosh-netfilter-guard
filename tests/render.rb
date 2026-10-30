#!/usr/bin/env ruby
# Renders a job template with a minimal stand-in for BOSH's p(): render.rb TEMPLATE PROPERTIES_YAML
# PROPERTIES_YAML holds the `netfilter_guard:` hash as it would appear in a manifest; spec defaults apply.
require 'erb'
require 'yaml'

spec = YAML.load_file(File.expand_path('../jobs/netfilter-guard/spec', __dir__))
props = (YAML.load_file(ARGV[1]) || {})

define_method(:p) do |key|
  val = key.split('.').reduce(props) { |h, k| h.is_a?(Hash) && h.key?(k) ? h[k] : (break nil) }
  return val unless val.nil?
  raise "no value or default for #{key}" unless spec['properties'].fetch(key, {}).key?('default')
  spec['properties'][key]['default']
end

print ERB.new(File.read(ARGV[0]), trim_mode: '-').result(binding)
