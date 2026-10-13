module Tune::Client::CLI
  DEFAULT_SERVER = {{ env("TUNE_DEFAULT_SERVER") || "" }}

  def self.run(arguments : Array(String)) : Int32
    args = arguments.dup
    keygen = args.first? == "keygen"
    args.shift if keygen
    server = ENV["TUNE_SERVER"]? || DEFAULT_SERVER
    name = ""
    identity_path : String? = nil
    show_help = false
    debug = false
    insecure = false
    positional = [] of String
    parser = OptionParser.new do |options|
      options.banner = "Usage: tune TARGET [options]\n       tune keygen [--identity PATH]"
      options.on("--server URL", "Tune Server origin (or TUNE_SERVER)") { |value| server = value }
      options.on("--name NAME", "Request a temporary name on a private server") { |value| name = value }
      options.on("--identity PATH", "Unencrypted OpenSSH Ed25519 private key") { |value| identity_path = File.expand_path(value) }
      options.on("--debug", "Enable diagnostic logging") { debug = true }
      options.on("--insecure-local", "Allow HTTP to a loopback development server") { insecure = true }
      options.on("--help", "Show help") { puts options; show_help = true }
      options.on("--version", "Show version") { puts "Tune v#{Tune::VERSION}"; show_help = true }
      options.unknown_args { |before, after| positional = before + after }
    end
    parser.parse(args)
    return 0 if show_help
    ::Log.setup(debug ? ::Log::Severity::Debug : ::Log::Severity::Info, ::Log::IOBackend.new(STDERR))
    default_identity = File.expand_path("~/.config/tune/id_ed25519")
    if keygen
      raise ArgumentError.new("keygen does not accept positional arguments") unless positional.empty?
      key_path = identity_path || default_identity
      generated = Security::Identity.generate(key_path.not_nil!)
      puts "#{key_path}\n#{key_path}.pub\n#{generated.fingerprint}"
      return 0
    end
    raise ArgumentError.new("Provide one TARGET; see tune --help") unless positional.size == 1
    raise ArgumentError.new("No public server configured; use --server URL or TUNE_SERVER") if server.empty?
    path = identity_path || (File.exists?(default_identity) ? default_identity : nil)
    identity = path ? Security::Identity.load(path.not_nil!) : nil
    target = Agent.target(positional[0])
    agent = Agent.new(target, URI.parse(server), name, identity, insecure)
    agent.on_connected do |url|
      puts "Tune v#{Tune::VERSION}\n\nLocal:  #{target}\nPublic: #{url}\n\nConnected"
      STDOUT.flush
    end
    Signal::INT.trap { agent.stop }
    Signal::TERM.trap { agent.stop }
    agent.run
    0
  rescue ex
    STDERR.puts "tune: #{ex.message}"
    1
  end
end
