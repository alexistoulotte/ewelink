require 'active_support'
require 'active_support/core_ext'
require 'byebug' if ENV['DEBUGGER']
require 'httparty'
require 'io/console'
require 'json'
require 'logger'
require 'openssl'
require 'optparse'
require 'set'
require 'timeout'
require 'websocket-client-simple'

module Ewelink

  mattr_accessor :logger
  self.logger = Logger.new(nil)

end

require_relative 'ewelink/api'
require_relative 'ewelink/error'
require_relative 'ewelink/runner'
