module Tune::Server::CLI
  def self.run(arguments : Array(String)) : Int32
    path : String? = nil
    bind : String? = nil
    domain : String? = nil
    keys : String? = nil
    show_help = false
    debug = false
    insecure = false
    positional = [] of String
    parser = OptionParser.new do |options|
      options.banner = "Usage: tune-server start PORT [options]"
      options.on("--bind ADDRESS", "Listener address") { |value| bind = value }
      options.on("--domain DOMAIN", "Base domain and control hostname") { |value| domain = value }
      options.on("--config PATH", "YAML configuration") { |value| path = value }
      options.on("--authorized-keys PATH", "Allowed OpenSSH Ed25519 public keys") { |value| keys = value }
      options.on("--debug", "Enable diagnostic logging") { debug = true }
      options.on("--insecure-local", "Loopback HTTP development mode") { insecure = true }
      options.on("--help", "Show help") { puts options; show_help = true }
      options.on("--version", "Show version") { puts "Tune Server v#{Tune::VERSION}"; show_help = true }
      options.unknown_args { |before, after| positional = before + after }
    end
    parser.parse(arguments.dup)
    return 0 if show_help
    raise ArgumentError.new("Expected start PORT; see tune-server --help") unless positional.size == 2 && positional[0] == "start"
    port = positional[1].to_i
    config = path ? Config.from_yaml(File.read(path.not_nil!)) : Config.from_yaml("{}")
    config.server.port = port
    config.server.bind = bind.not_nil! if bind
    config.server.domain = domain.not_nil! if domain
    config.auth.authorized_keys = keys.not_nil! if keys
    config.server.insecure_local = true if insecure
    config.logging.level = "debug" if debug
    config.validate
    severity = ::Log::Severity.parse(config.logging.level)
    ::Log.setup(severity, ::Log::IOBackend.new(STDERR))
    server = Server.new(config)
    Signal::INT.trap { spawn server.stop(grace: true) }
    Signal::TERM.trap { spawn server.stop(grace: true) }
    Signal::HUP.trap do
      begin
        updated = path ? Config.from_yaml(File.read(path.not_nil!)) : config
        updated.server.port = port
        updated.server.bind = bind.not_nil! if bind
        updated.server.domain = domain.not_nil! if domain
        updated.server.insecure_local = true if insecure
        updated.auth.authorized_keys = keys.not_nil! if keys
        server.reload(updated)
      rescue ex
        Tune::Log.error { "Cannot reload configuration: #{ex.message}" }
        server.reload
      end
    end
    server.run
    0
  rescue ex
    STDERR.puts "tune-server: #{ex.message}"
    1
  end
end
