require 'socket'
require_relative './can_open'

puts "Version #{CanOpen::VERSION} Platform "+ RUBY_PLATFORM



s = Socket.open();


