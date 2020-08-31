module Ewelink

  class Runner

    def run
      api = Api.new(options.slice(:email, :password, :phone_number))
      puts(JSON.pretty_generate(api.switches)) if options[:list_switches]
      puts(JSON.pretty_generate(api.rf_bridge_buttons)) if options[:list_rf_bridge_buttons]
      options[:turn_switches_on_uuids].each { |uuid| api.turn_switch!(uuid, :on) }
      options[:turn_switches_off_uuids].each { |uuid| api.turn_switch!(uuid, :off) }
      options[:press_rf_bridge_buttons_uuids].each { |uuid| api.press_rf_bridge_button!(uuid) }
      puts(JSON.pretty_generate(options[:switch_status_uuids].map { |uuid| [uuid, api.switch_on?(uuid) ? 'on' : 'off'] }.to_h))
    end

    private

    def options
      @options ||= begin
        options = { press_rf_bridge_buttons_uuids: [], turn_switches_off_uuids: [], turn_switches_on_uuids: [], switch_status_uuids: [] }
        parser = OptionParser.new do |opts|
          opts.banner = 'Manage eWeLink smart home devices'
          opts.version = File.read(File.expand_path('../../VERSION', __dir__)).strip
          opts.separator('')
          opts.separator('Usage: ewelink [options]')
          opts.separator('')
          opts.on('-e', '--email EMAIL', "eWeLink account's email (mandatory if phone number is not specified)") do |email|
            options[:email] = email
          end
          opts.on('-p', '--password PASSWORD', "eWeLink account's password (mandatory, prompted if not specified on command line)") do |password|
            options[:password] = password
          end
          opts.on('-n', '--phone-number PHONE_NUMBER', "eWeLink account's phone number (mandatory if email is not specified)") do |phone_number|
            options[:phone_number] = phone_number
          end
          opts.on('--list-switches', 'List all switches in JSON format') do
            options[:list_switches] = true
          end
          opts.on('--list-rf-bridge-buttons', 'List all RF 433MHz bridge buttons in JSON format') do
            options[:list_rf_bridge_buttons] = true
          end
          opts.on('--turn-switch-on SWITCH_UUID', 'Turn the switch with specified UUID on') do |uuid|
            options[:turn_switches_on_uuids] << uuid
          end
          opts.on('--turn-switch-off SWITCH_UUID', 'Turn the switch with specified UUID off') do |uuid|
            options[:turn_switches_off_uuids] << uuid
          end
          opts.on('--press-rf-bridge-button BUTTON_UUID', 'Press RF 433MHz bridge button with specified UUID') do |uuid|
            options[:press_rf_bridge_buttons_uuids] << uuid
          end
          opts.on('--switch-status SWITCH_UUID', 'Displays switch status of specified UUID') do |uuid|
            options[:switch_status_uuids] << uuid
          end
          opts.on('-v', '--verbose', 'Verbose mode') do
            Ewelink.logger.level = :debug
          end
        end
        arguments = parser.parse!
        if arguments.any?
          STDERR.puts("Invalid option specified: #{arguments.first}")
          STDERR.puts(parser.summarize)
          exit(1)
        end
        if options[:email].blank? && options[:phone_number].blank?
          STDERR.puts('Email or phone number must be specified')
          STDERR.puts(parser.summarize)
          exit(1)
        end
        if [:list_switches, :list_rf_bridge_buttons, :turn_switches_on_uuids, :turn_switches_off_uuids, :press_rf_bridge_buttons_uuids, :switch_status_uuids].map { |action| options[action] }.all?(&:blank?)
          STDERR.puts('An action must be specified (listing switches, press RF bridge button, etc.)')
          STDERR.puts(parser.summarize)
          exit(1)
        end
        while options[:password].blank?
          options[:password] = IO::console.getpass("Enter eWeLink account's password: ")
        end
        options
      end
    end

  end

end
