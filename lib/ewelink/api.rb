module Ewelink

  class Api

    APP_ID = 'oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq'.freeze
    APP_SECRET = '6Nz4n0xA8s8qdxQf2GqurZj2Fs55FUvM'.freeze
    DEFAULT_REGION = 'us'.freeze
    REQUEST_TIMEOUT = 10.seconds
    RF_BRIDGE_DEVICE_UIID = 28
    SWITCH_DEVICES_UIIDS = [1, 5, 6, 24].freeze
    URL = 'https://#{region}-api.coolkit.cc:8080'.freeze
    VERSION = 8
    WEB_SOCKET_CHECK_AUTHENTICATION_TIMEOUT = 30.seconds
    WEB_SOCKET_PING_TOLERANCE_FACTOR = 1.5
    SWITCH_STATUS_CHANGE_CHECK_TIMEOUT = 2.seconds
    WEB_SOCKET_WAIT_INTERVAL = 0.2.seconds

    attr_reader :email, :password, :phone_number

    def initialize(password:, async_actions: false, email: nil, phone_number: nil, update_devices_status_on_connect: false)
      @async_actions = async_actions.present?
      @email = email.presence.try(:strip)
      @mutexs = {}
      @password = password.presence || raise(Error.new(':password must be specified'))
      @phone_number = phone_number.presence.try(:strip)
      @update_devices_status_on_connect = update_devices_status_on_connect.present?
      @web_socket_authenticated = false
      @web_socket_switches_statuses = {}

      raise(Error.new(':email or :phone_number must be specified')) if email.blank? && phone_number.blank?

      start_web_socket_authentication_check_thread
    end

    def async_actions?
      @async_actions
    end

    def press_rf_bridge_button!(uuid)
      process_action do
        synchronize(:press_rf_bridge_button) do
          button = find_rf_bridge_button!(uuid)
          web_socket_wait_for(-> { web_socket_authenticated? }, initialize_web_socket: true) do
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
    end

    def reload
      Ewelink.logger.debug(self.class.name) { 'Reloading API (authentication token, api key, devices, region, connections,...)' }

      @web_socket_authenticated = false
      @web_socket_switches_statuses.clear

      [@web_socket_ping_thread, @web_socket_thread].each do |thread|
        next unless thread
        if Thread.current == thread
          thread[:stop] = true
        else
          thread.kill
        end
      end

      if @web_socket.present?
        begin
          @web_socket.close if @web_socket.open?
        rescue
          # Ignoring close errors
        end
      end

      %i(
        @authentication_infos
        @devices
        @last_web_socket_pong_at
        @region
        @rf_bridge_buttons
        @switches
        @web_socket_ping_interval
        @web_socket_ping_thread
        @web_socket_thread
        @web_socket_url
        @web_socket
      ).each do |variable|
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
                api_key:,
                channel: rf['rfChl'],
                device_id:,
                device_name:,
              }
              remote_info = device['tags']['zyx_info'].find { |info| info['buttonName'].find { |data| data.key?(button[:channel].to_s) } }.presence || next
              remote_name = remote_info['name'].try(:squish).presence || next
              button_info = remote_info['buttonName'].find { |info| info.key?(button[:channel].to_s) }.presence || next
              button_name = button_info.values.first.try(:squish).presence || next
              button.merge!({
                name: button_name,
                remote_name:,
                remote_type: remote_info['remote_type'],
              })
              button[:uuid] = Digest::UUID.uuid_v5(Digest::UUID::DNS_NAMESPACE, "#{button[:device_id]}/#{button[:channel]}")
              buttons << button
            end
          end
        end.tap { |buttons| Ewelink.logger.debug(self.class.name) { "Found #{buttons.size} RF 433MHz bridge button(s)" } }
      end
    end

    def switch_on?(uuid)
      switch = find_switch!(uuid)
      if @web_socket_switches_statuses[switch[:uuid]].nil?
        web_socket_wait_for(-> { web_socket_authenticated? }, initialize_web_socket: true) do
          Ewelink.logger.debug(self.class.name) { "Checking switch #{switch[:uuid].inspect} status" }
          params = {
            'action' => 'query',
            'apikey' => switch[:api_key],
            'deviceid' => switch[:device_id],
            'sequence' => web_socket_sequence,
            'ts' => 0,
            'userAgent' => 'app',
          }
          send_to_web_socket(JSON.generate(params))
        end
      end
      web_socket_wait_for(-> { !@web_socket_switches_statuses[switch[:uuid]].nil? }, initialize_web_socket: true) do
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
              api_key:,
              device_id:,
              model: device['productModel'],
              name:,
            }
            switch[:uuid] = Digest::UUID.uuid_v5(Digest::UUID::DNS_NAMESPACE, switch[:device_id])
            switches << switch
          end
        end.tap { |switches| Ewelink.logger.debug(self.class.name) { "Found #{switches.size} switch(es)" } }
      end
    end

    def turn_switch!(uuid, on)
      process_action do
        if ['on', :on, 'true'].include?(on)
          on = true
        elsif ['off', :off, 'false'].include?(on)
          on = false
        end
        switch = find_switch!(uuid)
        @web_socket_switches_statuses[switch[:uuid]] = nil
        web_socket_wait_for(-> { web_socket_authenticated? }, initialize_web_socket: true) do
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
        sleep(SWITCH_STATUS_CHANGE_CHECK_TIMEOUT)
        switch_on?(switch[:uuid]) # Waiting for switch status update
        true
      end
    end

    def update_devices_status_on_connect?
      @update_devices_status_on_connect
    end

    private

    def api_key
      authentication_infos[:api_key]
    end

    def authenticate_web_socket_api_key
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

    def authentication_headers
      { 'Authorization' => "Bearer #{authentication_token}" }
    end

    def authentication_infos
      synchronize(:authentication_infos) do
        @authentication_infos ||= begin
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
          response = rest_request(:post, '/api/user/login', { body:, headers: { 'Authorization' => "Sign #{Base64.encode64(OpenSSL::HMAC.digest('SHA256', APP_SECRET, body))}" } })
          raise(Error.new('Authentication token not found')) if response['at'].blank?
          raise(Error.new('API key not found')) if response['user'].blank? || response['user']['apikey'].blank?
          {
            authentication_token: response['at'].tap { Ewelink.logger.debug(self.class.name) { 'Authentication token found' } },
            api_key: response['user']['apikey'].tap { Ewelink.logger.debug(self.class.name) { 'API key found' } },
          }
        end
      end
    end

    def authentication_token
      authentication_infos[:authentication_token]
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

    def find_rf_bridge_button!(uuid)
      rf_bridge_buttons.find { |button| button[:uuid] == uuid } || raise(Error.new("No such RF bridge button with UUID: #{uuid.inspect}"))
    end

    def find_switch!(uuid)
      switches.find { |switch| switch[:uuid] == uuid } || raise(Error.new("No such switch with UUID: #{uuid.inspect}"))
    end

    def nonce
      SecureRandom.hex[0, 8]
    end

    def process_action(&block)
      return yield unless async_actions?
      @async_actions_thread_pool ||= Thread.pool(1)
      @async_actions_thread_pool.process(&block)
      true
    end

    def region
      @region ||= DEFAULT_REGION
    end

    def rest_request(method, path, options = {})
      url = "#{URL.gsub('#{region}', region)}#{path}"
      method = method.to_s.upcase
      headers = (options[:headers] || {}).reverse_merge('Content-Type' => 'application/json')
      Ewelink.logger.debug(self.class.name) { "#{method} #{url}" }
      response = HTTParty.send(method.downcase, url, options.merge(headers:).reverse_merge(timeout: REQUEST_TIMEOUT))
      raise(Error.new("#{method} #{url}: #{response.code}")) unless response.success?
      if response['error'] == 301 && response['region'].present?
        @region = response['region']
        Ewelink.logger.debug(self.class.name) { "Switched to region #{region.inspect}" }
        return rest_request(method, path, options)
      end
      remove_instance_variable(:@authentication_infos) if instance_variable_defined?(:@authentication_infos) && [401, 403].include?(response['error'])
      raise(Error.new("#{method} #{url}: #{response['error']} #{response['msg']}".strip)) if response['error'].present? && response['error'] != 0
      response.to_h
    rescue Errno::ECONNREFUSED, OpenSSL::OpenSSLError, SocketError, Timeout::Error => e
      raise Error.new(e)
    end

    def send_to_web_socket(message)
      web_socket.send(message)
    rescue => e
      reload
      raise Error.new(e)
    end

    def start_web_socket_authentication_check_thread
      raise Error.new('WebSocket authentication check must only be started once') if @web_socket_authentication_check_thread.present?

      @web_socket_authentication_check_thread = Thread.new do
        loop do
          Ewelink.logger.debug(self.class.name) { 'Checking if WebSocket is authenticated' }
          begin
            web_socket_wait_for(-> { web_socket_authenticated? }, initialize_web_socket: true) do
              Ewelink.logger.debug(self.class.name) { 'WebSocket is authenticated' }
            end
          rescue => e
            Ewelink.logger.error(self.class.name) { e }
          end
          sleep(WEB_SOCKET_CHECK_AUTHENTICATION_TIMEOUT)
        end
      end
    end

    def start_web_socket_ping_thread(interval)
      @last_web_socket_pong_at = Time.now
      @web_socket_ping_interval = interval
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

    def synchronize(name, &block)
      (@mutexs[name] ||= Mutex.new).synchronize(&block)
    end

    def web_socket
      if web_socket_outdated_ping?
        Ewelink.logger.warn(self.class.name) { 'WebSocket ping is outdated' }
        reload
      end

      synchronize(:web_socket) do
        next @web_socket if @web_socket

        # Initializes caches before opening WebSocket: important in order to
        # NOT cumulate requests Timeouts from #web_socket_wait_for.
        api_key
        web_socket_url

        Ewelink.logger.debug(self.class.name) { "Opening WebSocket to #{web_socket_url.inspect}" }

        @web_socket_thread = Thread.new do
          EventMachine.run do
            @web_socket = Faye::WebSocket::Client.new(web_socket_url)

            @web_socket.on(:close) do
              Ewelink.logger.debug(self.class.name) { 'WebSocket closed' }
              reload
            end

            @web_socket.on(:open) do
              Ewelink.logger.debug(self.class.name) { 'WebSocket opened' }
              @last_web_socket_pong_at = Time.now
              authenticate_web_socket_api_key
            end

            @web_socket.on(:message) do |event|
              message = event.data

              if message == 'pong'
                Ewelink.logger.debug(self.class.name) { "Received WebSocket #{message.inspect} message" }
                @last_web_socket_pong_at = Time.now
                next
              end

              begin
                json = JSON.parse(message)
              rescue
                Ewelink.logger.error(self.class.name) { 'WebSocket JSON parse error' }
                reload
                next
              end

              if json.key?('error') && json['error'] != 0
                Ewelink.logger.error(self.class.name) { "WebSocket message error: #{message.inspect}" }
                reload
                next
              end

              if !@web_socket_ping_thread && json.key?('config') && json['config']['hb'] == 1 && json['config']['hbInterval'].present?
                start_web_socket_ping_thread(json['config']['hbInterval'] + 7)
              end

              if json['apikey'].present? && !@web_socket_authenticated && json['apikey'] == api_key
                @web_socket_authenticated = true
                Ewelink.logger.debug(self.class.name) { "WebSocket successfully authenticated API key: #{json['apikey'].truncate(16).inspect}" }
                Thread.new { switches.each { |switch| switch_on?(switch[:uuid]) } } if update_devices_status_on_connect?
              end

              if json['deviceid'].present? && json['params'].is_a?(Hash) && json['params']['switch'].present?
                switch = switches.find { |item| item[:device_id] == json['deviceid'] }
                if switch.present?
                  @web_socket_switches_statuses[switch[:uuid]] = json['params']['switch']
                  Ewelink.logger.debug(self.class.name) { "Switch #{switch[:uuid].inspect} is #{@web_socket_switches_statuses[switch[:uuid]]}" }
                end
              end
            end
          end
        end

        web_socket_wait_for(-> { @web_socket.present? }) do
          @web_socket
        end
      end
    end

    def web_socket_authenticated?
      @web_socket_authenticated.present?
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

    def web_socket_wait_for(condition, initialize_web_socket: false)
      web_socket if initialize_web_socket
      begin
        Timeout.timeout(REQUEST_TIMEOUT) do
          sleep(WEB_SOCKET_WAIT_INTERVAL) until condition.call
          block_given? ? yield : true
        end
      rescue => e
        reload
        raise Error.new(e)
      end
    end

  end

end
