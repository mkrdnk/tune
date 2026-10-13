require "./spec_helper"

class Tune::TLS::ACME
  def inject_stale_nonce
    @nonce = "intentionally-invalid-test-nonce"
  end
end

class Tune::TLS::Manager
  def force_renewal_for_test(hostname : String)
    certificate = @certificates[hostname]
    @certificates[hostname] = Tune::TLS::Certificate.new(hostname, certificate.context, Time.utc - 90.days, Time.utc + 1.day)
    @acme.inject_stale_nonce
  end
end

if directory = ENV["TUNE_TEST_ACME_DIRECTORY"]?
  describe "ACME against Pebble" do
    it "issues through HTTP-01, serves SNI HTTPS, and reuses persisted certificates" do
      options = Tune::Config::ACMEOptions.from_yaml("{}")
      options.directory_url = directory
      options.terms_agreed = true
      options.data_dir = ENV["TUNE_TEST_ACME_STATE"]
      manager = Tune::TLS::Manager.new(options)
      challenge = HTTP::Server.new do |context|
        hostname = Tune::HTTPWire.hostname(context.request.headers)
        answer = manager.not_nil!.challenge(hostname, context.request.resource)
        context.response.status_code = answer ? 200 : 404
        context.response.print(answer || "missing")
      end
      challenge.bind_tcp("127.0.0.1", ENV["TUNE_TEST_ACME_HTTP_PORT"].to_i)
      spawn challenge.listen
      manager.not_nil!.ensure_certificate("localhost")
      manager.not_nil!.ensure_certificate("tunnel.localhost")
      manager.not_nil!.available?("localhost").should be_true
      manager.not_nil!.available?("tunnel.localhost").should be_true
      manager.not_nil!.available?("unknown.localhost").should be_false
      manager.not_nil!.challenge("other.localhost", "/.well-known/acme-challenge/unknown").should be_nil
      server = HTTP::Server.new { |context| context.response.print "secure" }
      address = server.bind_tls("127.0.0.1", 0, manager.not_nil!.context("localhost"))
      spawn server.listen
      tcp = TCPSocket.new("127.0.0.1", address.port)
      socket = OpenSSL::SSL::Socket::Client.new(tcp, context: OpenSSL::SSL::Context::Client.new, hostname: "tunnel.localhost", sync_close: true)
      Tune::HTTPWire.write_head(socket, "GET / HTTP/1.1", HTTP::Headers{"Host" => "tunnel.localhost", "Connection" => "close"})
      head = Tune::HTTPWire.head(socket)
      Tune::HTTPWire.status(head).should eq(200)
      Tune::HTTPWire::Body.new(socket, head.headers, response: true).gets_to_end.should eq("secure")
      socket.close
      previous = File.read(File.join(options.data_dir, "cert-tunnel.localhost.pem"))
      manager.not_nil!.force_renewal_for_test("tunnel.localhost")
      manager.not_nil!.ensure_certificate("tunnel.localhost")
      File.read(File.join(options.data_dir, "cert-tunnel.localhost.pem")).should_not eq(previous)
      manager.not_nil!.available?("tunnel.localhost").should be_true
      state = File.read(File.join(options.data_dir, "state.json"))
      account = File.read(File.join(options.data_dir, "account-key.pem"))
      manager.not_nil!.close
      manager = Tune::TLS::Manager.new(options)
      manager.not_nil!.ensure_certificate("localhost")
      manager.not_nil!.ensure_certificate("tunnel.localhost")
      File.read(File.join(options.data_dir, "state.json")).should eq(state)
      File.read(File.join(options.data_dir, "account-key.pem")).should eq(account)
      File.info(File.join(options.data_dir, "cert-localhost.pem")).permissions.value.should eq(0o600)
      manager.not_nil!.close
      challenge.close
      server.close

      application = HTTP::Server.new do |context|
        if context.request.path == "/echo"
          context.request.body.try { |body| IO.copy(body, context.response) }
        else
          context.response.print "secure tunnel"
        end
      end
      local = application.bind_unused_port("127.0.0.1")
      spawn application.listen
      config = Tune::Config.from_yaml("{}")
      config.server.domain = "localhost"
      config.server.port = 0
      config.auth.mode = "public"
      config.tls.mode = "acme"
      config.tls.acme = options
      options.http_port = ENV["TUNE_TEST_ACME_HTTP_PORT"].to_i
      tune = Tune::Server::Server.new(config)
      config.server.public_url = "https://localhost:#{tune.port}"
      spawn tune.run
      agent = Tune::Client::Agent.new(URI.parse("http://127.0.0.1:#{local.port}"), URI.parse(config.server.public_url))
      session = agent.connect
      spawn session.run
      hostname = URI.parse(agent.public_url.not_nil!).host.not_nil!
      tcp = TCPSocket.new("127.0.0.1", tune.port)
      socket = OpenSSL::SSL::Socket::Client.new(tcp, context: OpenSSL::SSL::Context::Client.new, hostname: hostname, sync_close: true)
      Tune::HTTPWire.write_head(socket, "GET / HTTP/1.1", HTTP::Headers{"Host" => hostname, "Connection" => "close"})
      head = Tune::HTTPWire.head(socket)
      Tune::HTTPWire::Body.new(socket, head.headers, response: true).gets_to_end.should eq("secure tunnel")
      socket.close
      tcp = TCPSocket.new("127.0.0.1", tune.port)
      socket = OpenSSL::SSL::Socket::Client.new(tcp, context: OpenSSL::SSL::Context::Client.new, hostname: hostname, sync_close: true)
      binary = Bytes.new(2_097_152, 219_u8)
      Tune::HTTPWire.write_head(socket, "POST /echo HTTP/1.1", HTTP::Headers{"Host" => hostname, "Content-Length" => binary.size.to_s, "Connection" => "close"})
      upload = socket
      completed = Channel(Nil).new(1)
      spawn do
        upload.write(binary)
        upload.flush
        completed.send(nil)
      end
      head = Tune::HTTPWire.head(socket)
      Tune::HTTPWire::Body.new(socket, head.headers, response: true).gets_to_end.to_slice.should eq(binary)
      completed.receive
      socket.close
    ensure
      agent.try &.stop
      tune.try &.stop
      application.try { |app| app.close unless app.closed? }
      manager.try &.close
      challenge.try { |http| http.close unless http.closed? }
      server.try { |http| http.close unless http.closed? }
    end
  end
end
