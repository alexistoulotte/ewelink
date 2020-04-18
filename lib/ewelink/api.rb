module Ewelink

  class Api

    APP_ID = 'oeVkj2lYFGnJu5XUtWisfW4utiN4u9Mq'
    APP_SECRET = '6Nz4n0xA8s8qdxQf2GqurZj2Fs55FUvM'
    DEFAULT_REGION = 'us'
    RF_BRIDGE_DEVICE_UIID = 28
    SWITCH_DEVICES_UIIDS = [1, 5, 6, 24]
    TIMEOUT = 10
    URL = 'https://#{region}-api.coolkit.cc:8080'
    UUID_NAMESPACE = 'e25750fb-3710-41af-b831-23224f4dd609';
    VERSION = 8

    attr_reader :email, :password, :phone_number

    def initialize(email: nil, password:, phone_number: nil)
      @email = email.presence.try(:strip)
      @mutexs = {}
      @password = password.presence || raise(Error.new(":password must be specified"))
      @phone_number = phone_number.presence.try(:strip)
      raise(Error.new(":email or :phone_number must be specified")) if email.blank? && phone_number.blank?
    end

    def press_rf_bridge_button!(uuid)
      synchronize(:press_rf_bridge_button) do
        button = find_rf_bridge_button!(uuid)
        params = {
          'appid' => APP_ID,
          'deviceid' => button[:device_id],
          'nonce' => nonce,
          'params' => {
            'cmd' => 'transmit',
            'rfChl' => button[:channel],
          },
          'ts' => Time.now.to_i,
          'version' => VERSION,
        }
        http_request(:post, '/api/user/device/status', body: JSON.generate(params), headers: authentication_headers)
        true
      end
    end

    def reload
      Ewelink.logger.debug(self.class.name) { 'Reloading API (authentication token, devices & region cache)' }
      [:@authentication_token, :@devices, :@rf_bridge_buttons, :@region, :@switches].each do |variable|
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
            device_id = device['deviceid'].presence || next
            device_name = device['name'].presence || next
            buttons = device['params']['rfList'].each do |rf|
              button = {
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
      params = {
        'appid' => APP_ID,
        'deviceid' => switch[:device_id],
        'nonce' => nonce,
        'ts' => Time.now.to_i,
        'version' => VERSION,
      }
      response = http_request(:get, '/api/user/device/status', headers: authentication_headers, query: params)
      response['params']['switch'] == 'on'
    end

    def switches
      synchronize(:switches) do
        @switches ||= [].tap do |switches|
          switch_devices = devices.select { |device| SWITCH_DEVICES_UIIDS.include?(device['uiid']) }
          switch_devices.each do |device|
            device_id = device['deviceid'].presence || next
            name = device['name'].presence || next
            switch = {
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
      params = {
        'appid' => APP_ID,
        'deviceid' => switch[:device_id],
        'nonce' => nonce,
        'params' => {
          'switch' => on ? 'on' : 'off',
        },
        'ts' => Time.now.to_i,
        'version' => VERSION,
      }
      http_request(:post, '/api/user/device/status', body: JSON.generate(params), headers: authentication_headers)
      true
    end

    private

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
          response = http_request(:post, '/api/user/login', { body: body, headers: { 'Authorization' => "Sign #{Base64.encode64(OpenSSL::HMAC.digest('SHA256', APP_SECRET, body))}" } })
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
          response = http_request(:get, '/api/user/device', headers: authentication_headers, query: params)
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

    def region
      @region ||= DEFAULT_REGION
    end

    def http_request(method, path, options = {})
      url = "#{URL.gsub('#{region}', region)}#{path}"
      method = method.to_s.upcase
      headers = (options[:headers] || {}).reverse_merge('Content-Type' => 'application/json')
      Ewelink.logger.debug(self.class.name) { "#{method} #{url}" }
      response = HTTParty.send(method.downcase, url, options.merge(headers: headers).reverse_merge(timeout: TIMEOUT))
      raise(Error.new("#{method} #{url}: #{response.code}")) unless response.success?
      if response['error'] == 301 && response['region'].present?
        @region = response['region']
        Ewelink.logger.debug(self.class.name) { "Switched to region #{region.inspect}" }
        return http_request(method, path, options)
      end
      remove_instance_variable(:@authentication_token) if instance_variable_defined?(:@authentication_token) && [401, 403].include?(response['error'])
      raise(Error.new("#{method} #{url}: #{response['error']} #{response['msg']}".strip)) if response['error'].present? && response['error'] != 0
      response
    rescue Errno::ECONNREFUSED, OpenSSL::OpenSSLError, SocketError, Timeout::Error => e
      raise Error.new(e)
    end

    def synchronize(name, &block)
      (@mutexs[name] ||= Mutex.new).synchronize(&block)
    end

  end

end
