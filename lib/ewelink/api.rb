module Ewelink

  class Api

    APP_ID = 'oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq'
    APP_SECRET = '6Nz4n0xA8s8qdxQf2GqurZj2Fs55FUvM'
    DEFAULT_REGION = 'us'
    REQUEST_TIMEOUT = 10.seconds
    RF_BRIDGE_DEVICE_UIID = 28
    SWITCH_DEVICES_UIIDS = [1, 5, 6, 24]
    URL = 'https://#{region}-api.coolkit.cc:8080'
    UUID_NAMESPACE = 'e25750fb-3710-41af-b831-23224f4dd609';
    VERSION = 8
    WEB_SOCKET_PING_TOLERANCE_FACTOR = 1.5
    WEB_SOCKET_WAIT_INTERVAL = 0.2.seconds

    attr_reader :email, :password, :phone_number

    def initialize(email: nil, password:, phone_number: nil)
      @email = email.presence.try(:strip)
      @mutexs = {}
      @password = password.presence || raise(Error.new(":password must be specified"))
      @phone_number = phone_number.presence.try(:strip)
      @web_socket_authenticated_api_keys = Set.new
      @web_socket_switches_statuses = {}
      raise(Error.new(":email or :phone_number must be specified")) if email.blank? && phone_number.blank?
    end

    def press_rf_bridge_button!(uuid)
      synchronize(:press_rf_bridge_button) do
        button = find_rf_bridge_button!(uuid)
        web_socket_wait_for(-> { web_socket_authenticated? }) do
          params = {
            'action' => 'update',
            'apikey' => button[:api_key],
            'deviceid' => button[:device_id],
            'params' => {
              'cmd' => 'transmit',
              'rfChl' => button[:channel],
            },
            'sequence' => web_socket_sequence,
            'ts' => 0,
            'userAgent' => 'app',
          }
          Ewelink.logger.debug(self.class.name) { "Pressing RF bridge button #{button[:uuid].inspect}" }
          send_to_web_socket(JSON.generate(params))
          true
        end
      end
    end

    def reload
      Ewelink.logger.debug(self.class.name) { 'Reloading API (authentication token, devices, region, connections,...)' }
      dispose_web_socket
      [
        :@api_keys,
        :@authentication_token,
        :@devices,
        :@region,
        :@rf_bridge_buttons,
        :@switches,
      ].each do |variable|
        remove_instance_variable(variable) if instance_variable_defined?(variable)
      end
      self
    end

    def rf_bridge_buttons
      synchronize(:rf_bridge_buttons) do
        @rf_bridge_buttons ||= [].tap do |buttons|
          rf_bridge_devices = devices.select { |device| device['uiid'] == RF_BRIDGE_DEVICE_UIID }.tap do |devices|
            Ewelink.logger.debug(self.class.name) { "Found #{devices.size} RF 433MHz bridge device(s)" }
          end
          rf_bridge_devices.each do |device|
            api_key = device['apikey'].presence || next
            device_id = device['deviceid'].presence || next
            device_name = device['name'].presence || next
            buttons = device['params']['rfList'].each do |rf|
              button = {
                api_key: api_key,
                channel: rf['rfChl'],
                device_id: device_id,
                device_name: device_name,
              }
              remote_info = device['tags']['zyx_info'].find { |info| info['buttonName'].find { |data| data.key?(button[:channel].to_s) } }.presence || next
              remote_name = remote_info['name'].try(:squish).presence || next
              button_info = remote_info['buttonName'].find { |info| info.key?(button[:channel].to_s) }.presence || next
              button_name = button_info.values.first.try(:squish).presence || next
              button.merge!({
                name: button_name,
                remote_name: remote_name,
                remote_type: remote_info['remote_type'],
              })
              button[:uuid] = Digest::UUID.uuid_v5(UUID_NAMESPACE, "#{button[:device_id]}/#{button[:channel]}")
              buttons << button
            end
          end
        end.tap { |buttons| Ewelink.logger.debug(self.class.name) { "Found #{buttons.size} RF 433MHz bridge button(s)" } }
      end
    end

    def switch_on?(uuid)
      switch = find_switch!(uuid)
      if @web_socket_switches_statuses[switch[:uuid]].nil?
        params = {
          'action' => 'query',
          'apikey' => switch[:api_key],
          'deviceid' => switch[:device_id],
          'sequence' => web_socket_sequence,
          'ts' => 0,
          'userAgent' => 'app',
        }
        web_socket_wait_for(-> { web_socket_authenticated? }) do
          Ewelink.logger.debug(self.class.name) { "Checking switch #{switch[:uuid].inspect} status" }
          send_to_web_socket(JSON.generate(params))
        end
      end
      web_socket_wait_for(-> { !@web_socket_switches_statuses[switch[:uuid]].nil? }) do
        Ewelink.logger.debug(self.class.name) { "Switch #{switch[:uuid].inspect} is #{@web_socket_switches_statuses[switch[:uuid]]}" }
        @web_socket_switches_statuses[switch[:uuid]] == 'on'
      end
    end

    def switches
      synchronize(:switches) do
        @switches ||= [].tap do |switches|
          switch_devices = devices.select { |device| SWITCH_DEVICES_UIIDS.include?(device['uiid']) }
          switch_devices.each do |device|
            api_key = device['apikey'].presence || next
            device_id = device['deviceid'].presence || next
            name = device['name'].presence || next
            switch = {
              api_key: api_key,
              device_id: device_id,
              name: name,
            }
            switch[:uuid] = Digest::UUID.uuid_v5(UUID_NAMESPACE, switch[:device_id])
            switches << switch
          end
        end.tap { |switches| Ewelink.logger.debug(self.class.name) { "Found #{switches.size} switch(es)" } }
      end
    end

    def turn_switch!(uuid, on)
      if ['on', :on, 'true'].include?(on)
        on = true
      elsif ['off', :off, 'false'].include?(on)
        on = false
      end
      switch = find_switch!(uuid)
      @web_socket_switches_statuses[switch[:uuid]] = nil
      web_socket_wait_for(-> { web_socket_authenticated? }) do
        params = {
          'action' => 'update',
          'apikey' => switch[:api_key],
          'deviceid' => switch[:device_id],
          'params' => {
            'switch' => on ? 'on' : 'off',
          },
          'sequence' => web_socket_sequence,
          'ts' => 0,
          'userAgent' => 'app',
        }
        Ewelink.logger.debug(self.class.name) { "Turning switch #{switch[:uuid].inspect} #{on ? 'on' : 'off'}" }
        send_to_web_socket(JSON.generate(params))
      end
      switch_on?(switch[:uuid]) # Waiting for switch status update
      true
    end

    private

    def api_keys
      synchronize(:api_keys) do
        @api_keys ||= Set.new(devices.map { |device| device['apikey'] })
      end
    end

    def authentication_headers
      { 'Authorization' => "Bearer #{authentication_token}" }
    end

    def authentication_token
      synchronize(:authentication_token) do
        @authentication_token ||= begin
          params = {
            'appid' => APP_ID,
            'imei' => SecureRandom.uuid.upcase,
            'nonce' => nonce,
            'password' => password,
            'ts' => Time.now.to_i,
            'version' => VERSION,
          }
          if email.present?
            params['email'] = email
          else
            params['phoneNumber'] = phone_number
          end
          body = JSON.generate(params)
          response = rest_request(:post, '/api/user/login', { body: body, headers: { 'Authorization' => "Sign #{Base64.encode64(OpenSSL::HMAC.digest('SHA256', APP_SECRET, body))}" } })
          raise(Error.new('Authentication token not found')) if response['at'].blank?
          response['at'].tap { Ewelink.logger.debug(self.class.name) { 'Authentication token found' } }
        end
      end
    end

    def devices
      synchronize(:devices) do
        @devices ||= begin
          params = {
            'appid' => APP_ID,
            'getTags' => 1,
            'nonce' => nonce,
            'ts' => Time.now.to_i,
            'version' => VERSION,
          }
          response = rest_request(:get, '/api/user/device', headers: authentication_headers, query: params)
          response['devicelist'].tap { |devices| Ewelink.logger.debug(self.class.name) { "Found #{devices.size} device(s)" } }
        end
      end
    end

    def dispose_web_socket
      @web_socket_authenticated_api_keys.clear
      @web_socket_switches_statuses.clear

      if @web_socket_ping_thread
        if Thread.current == @web_socket_ping_thread
          Thread.current[:stop] = true
        else
          @web_socket_ping_thread.kill
        end
      end

      if @web_socket.present?
        begin
          @web_socket.close if @web_socket.open?
        rescue
          # Ignoring close errors
        end
      end

      [
        :@last_web_socket_pong_at,
        :@web_socket_ping_interval,
        :@web_socket_ping_thread,
        :@web_socket_url,
        :@web_socket,
      ].each do |variable|
        remove_instance_variable(variable) if instance_variable_defined?(variable)
      end
    end

    def find_rf_bridge_button!(uuid)
      rf_bridge_buttons.find { |button| button[:uuid] == uuid } || raise(Error.new("No such RF bridge button with UUID: #{uuid.inspect}"))
    end

    def find_switch!(uuid)
      switches.find { |switch| switch[:uuid] == uuid } || raise(Error.new("No such switch with UUID: #{uuid.inspect}"))
    end

    def nonce
      SecureRandom.hex[0, 8]
    end

    def region
      @region ||= DEFAULT_REGION
    end

    def rest_request(method, path, options = {})
      url = "#{URL.gsub('#{region}', region)}#{path}"
      method = method.to_s.upcase
      headers = (options[:headers] || {}).reverse_merge('Content-Type' => 'application/json')
      Ewelink.logger.debug(self.class.name) { "#{method} #{url}" }
      response = HTTParty.send(method.downcase, url, options.merge(headers: headers).reverse_merge(timeout: REQUEST_TIMEOUT))
      raise(Error.new("#{method} #{url}: #{response.code}")) unless response.success?
      if response['error'] == 301 && response['region'].present?
        @region = response['region']
        Ewelink.logger.debug(self.class.name) { "Switched to region #{region.inspect}" }
        return rest_request(method, path, options)
      end
      remove_instance_variable(:@authentication_token) if instance_variable_defined?(:@authentication_token) && [401, 403].include?(response['error'])
      raise(Error.new("#{method} #{url}: #{response['error']} #{response['msg']}".strip)) if response['error'].present? && response['error'] != 0
      response.to_h
    rescue Errno::ECONNREFUSED, OpenSSL::OpenSSLError, SocketError, Timeout::Error => e
      raise Error.new(e)
    end

    def send_to_web_socket(data)
      if web_socket_outdated_ping?
        Ewelink.logger.warn(self.class.name) { 'WebSocket ping is outdated' }
        dispose_web_socket
      end
      web_socket.send(data)
    rescue
      dispose_web_socket
      raise
    end

    def synchronize(name, &block)
      (@mutexs[name] ||= Mutex.new).synchronize(&block)
    end

    def web_socket
      synchronize(:web_socket) do
        @web_socket ||= begin
          api = self

          WebSocket::Client::Simple.connect(web_socket_url) do |web_socket|
            Ewelink.logger.debug(self.class.name) { "Opening WebSocket to #{web_socket_url.inspect}" }

            web_socket.on(:close) do
              api.instance_eval do
                Ewelink.logger.debug(self.class.name) { 'WebSocket closed' }
                dispose_web_socket
              end
            end

            web_socket.on(:error) do |e|
              api.instance_eval do
                Ewelink.logger.warn(self.class.name) { "WebSocket error: #{e}" }
                dispose_web_socket
              end
            end

            web_socket.on(:message) do |message|
              api.instance_eval do
                if message.data == 'pong'
                  Ewelink.logger.debug(self.class.name) { "Received WebSocket #{message.data.inspect} message" }
                  @last_web_socket_pong_at = Time.now
                  next
                end

                begin
                  response = JSON.parse(message.data)
                rescue => e
                  Ewelink.logger.error(self.class.name) { "WebSocket JSON parse error" }
                  next
                end

                if response.key?('error') && response['error'] != 0
                  Ewelink.logger.error(self.class.name) { "WebSocket message error: #{message.data}" }
                  next
                end

                if !@web_socket_ping_thread && response.key?('config') && response['config']['hb'] == 1 && response['config']['hbInterval'].present?
                  @last_web_socket_pong_at = Time.now
                  @web_socket_ping_interval = response['config']['hbInterval'] + 7
                  Ewelink.logger.debug(self.class.name) { "Creating thread for WebSocket ping every #{@web_socket_ping_interval} seconds" }
                  @web_socket_ping_thread = Thread.new do
                    loop do
                      break if Thread.current[:stop]
                      sleep(@web_socket_ping_interval)
                      Ewelink.logger.debug(self.class.name) { 'Sending WebSocket ping' }
                      send_to_web_socket('ping')
                    end
                  end
                end

                if response['apikey'].present? && !@web_socket_authenticated_api_keys.include?(response['apikey'])
                  @web_socket_authenticated_api_keys << response['apikey']
                  Ewelink.logger.debug(self.class.name) { "WebSocket successfully authenticated API key: #{response['apikey'].truncate(16).inspect}" }
                end

                if response['deviceid'].present? && response['params'].is_a?(Hash) && response['params']['switch'].present?
                  switch = switches.find { |switch| switch[:device_id] == response['deviceid'] }
                  @web_socket_switches_statuses[switch[:uuid]] = response['params']['switch'] if switch.present?
                end
              end
            end

            web_socket.on(:open) do
              api.instance_eval do
                Ewelink.logger.debug(self.class.name) { 'WebSocket opened' }
                api_keys.each do |api_key|
                  params = {
                    'action' => 'userOnline',
                    'apikey' => api_key,
                    'appid' => APP_ID,
                    'at' => authentication_token,
                    'nonce' => nonce,
                    'sequence' => web_socket_sequence,
                    'ts' => Time.now.to_i,
                    'userAgent' => 'app',
                    'version' => VERSION,
                  }
                  Ewelink.logger.debug(self.class.name) { "Authenticating WebSocket API key: #{api_key.truncate(16).inspect}" }
                  send_to_web_socket(JSON.generate(params))
                end
              end
            end
          end
        end
      end
    end

    def web_socket_authenticated?
      api_keys == @web_socket_authenticated_api_keys
    end

    def web_socket_outdated_ping?
      @last_web_socket_pong_at.present? && @web_socket_ping_interval.present? && @last_web_socket_pong_at < (@web_socket_ping_interval * WEB_SOCKET_PING_TOLERANCE_FACTOR).seconds.ago
    end

    def web_socket_sequence
      (Time.now.to_f * 1000).round.to_s
    end

    def web_socket_url
      synchronize(:web_socket_url) do
        @web_socket_url ||= begin
          params = {
            'accept' => 'ws',
            'appid' => APP_ID,
            'nonce' => nonce,
            'ts' => Time.now.to_i,
            'version' => VERSION,
          }
          response = rest_request(:post, '/dispatch/app', body: JSON.generate(params), headers: authentication_headers)
          raise('Error while getting WebSocket URL') unless response['error'] == 0
          domain = response['domain'].presence || raise("Can't get WebSocket server domain")
          port = response['port'].presence || raise("Can't get WebSocket server port")
          "wss://#{domain}:#{port}/api/ws".tap { |url| Ewelink.logger.debug(self.class.name) { "WebSocket URL is: #{url.inspect}" } }
        end
      end
    end

    def web_socket_wait_for(condition, &block)
      web_socket # Initializes WebSocket
      Timeout.timeout(REQUEST_TIMEOUT) do
        loop do
          if condition.call
            return yield if block_given?
            return true
          end
          sleep(WEB_SOCKET_WAIT_INTERVAL)
        end
      end
    end

  end

end
