require 'active_support'
require 'active_support/core_ext'
require 'byebug' if ENV['DEBUGGER']
require 'eventmachine'
require 'faye/websocket'
require 'httparty'
require 'io/console'
require 'json'
require 'logger'
require 'openssl'
require 'optparse'
require 'set'
require 'thread/pool'
require 'timeout'

module Ewelink

  mattr_accessor :logger
  self.logger = Logger.new(nil)

end

require_relative 'ewelink/api'
require_relative 'ewelink/error'
require_relative 'ewelink/runner'
