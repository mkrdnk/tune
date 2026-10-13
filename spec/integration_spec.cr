require "./spec_helper"

class TunnelFixture
  getter app : HTTP::Server
  getter server : Tune::Server::Server
  getter agent : Tune::Client::Agent
  getter hostname : String
  getter app_port : Int32
  getter gate = Channel(Nil).new(1)

  def initialize(identity : Tune::Security::Identity? = nil, keys : String? = nil)
    @app = HTTP::Server.new do |context|
      case context.request.path
      when "/large"
        context.response.content_type = "application/octet-stream"
        128.times { context.response.write(Bytes.new(16_384, 213_u8)) }
      when "/echo"
        context.response.status_code = 201
        context.response.headers.add("Set-Cookie", "a=1")
        context.response.headers.add("Set-Cookie", "b=2")
        context.request.body.try { |body| IO.copy(body, context.response) }
      when "/forwarded"
        context.response.print context.request.headers["X-Forwarded-For"]
      when "/early"
        context.response.status_code = 413
        context.response.print "rejected"
      when "/slow"
        context.response.print "first"
        context.response.flush
        @gate.receive
        context.response.print "last"
      else
        context.response.print "#{context.request.method} #{context.request.resource}"
      end
    end
    address = @app.bind_unused_port("127.0.0.1")
    @app_port = address.port
    spawn @app.listen
    config = Tune::Config.from_yaml("{}")
    config.server.domain = "127.0.0.1"
    config.server.port = 0
    config.server.insecure_local = true
    config.auth.mode = keys ? "private" : "public"
    config.auth.authorized_keys = keys if keys
    config.limits.bytes_per_second = 100_000_000_i64
    @server = Tune::Server::Server.new(config)
    config.server.public_url = "http://127.0.0.1:#{@server.port}"
    spawn @server.run
    @agent = Tune::Client::Agent.new(URI.parse("http://127.0.0.1:#{address.port}"), URI.parse(config.server.public_url), "", identity, true)
    session = @agent.connect
    @hostname = URI.parse(@agent.public_url.not_nil!).host.not_nil!
    spawn session.run
  end

  def request(method = "GET", path = "/", body : String? = nil, extra = HTTP::Headers.new) : HTTP::Client::Response
    headers = extra.dup
    headers["Host"] = hostname
    client = HTTP::Client.new("127.0.0.1", server.port)
    client.read_timeout = 10.seconds
    client.exec(method, path, headers, body)
  ensure
    client.try &.close
  end

  def close
    agent.stop
    server.stop
    app.close
  end
end

describe "HTTP tunnel" do
  it "forwards methods, queries, JSON, status and repeated headers" do
    fixture = TunnelFixture.new
    fixture.request("GET", "/?x=%2F&a=2").body.should eq("GET /?x=%2F&a=2")
    %w(POST PUT PATCH DELETE).each do |method|
      response = fixture.request(method, "/echo", "{\"hello\":true}", HTTP::Headers{"Content-Type" => "application/json"})
      response.status_code.should eq(201)
      response.body.should eq("{\"hello\":true}")
      response.headers.get("Set-Cookie").should eq(["a=1", "b=2"])
    end
    fixture.request("HEAD").body.should be_empty
    fixture.request("GET", "/forwarded", extra: HTTP::Headers{"X-Forwarded-For" => "forged"}).body.should eq("127.0.0.1")
  ensure
    fixture.try &.close
  end

  it "streams large binary uploads and downloads across many windows" do
    fixture = TunnelFixture.new
    data = String.new(Bytes.new(2_097_152, 213_u8))
    fixture.request("POST", "/echo", data).body.should eq(data)
    fixture.request("GET", "/large").body.should eq(data)
  ensure
    fixture.try &.close
  end

  it "multiplexes concurrent requests" do
    fixture = TunnelFixture.new
    results = Channel(Bool).new(16)
    16.times do |index|
      spawn do
        begin
          results.send(fixture.request("GET", "/#{index}").body == "GET /#{index}")
        rescue
          results.send(false)
        end
      end
    end
    16.times do
      select
      when result = results.receive
        result.should be_true
      when timeout(15.seconds)
        fail "Concurrent request stalled"
      end
    end
  ensure
    fixture.try &.close
  end

  it "authenticates a private client and disconnects it on revocation" do
    directory = File.join(Dir.tempdir, "tune-auth-#{Random::Secure.hex(8)}")
    path = File.join(directory, "key")
    begin
      identity = Tune::Security::Identity.generate(path)
      fixture = TunnelFixture.new(identity, path + ".pub")
      fixture.request.status_code.should eq(200)
      File.write(path + ".pub", "")
      fixture.server.reload
      fixture.server.registry.entries.all?(&.ws.closed?).should be_true
    ensure
      fixture.try &.close
      File.delete(path) if File.exists?(path)
      File.delete(path + ".pub") if File.exists?(path + ".pub")
      Dir.delete(directory) if Dir.exists?(directory)
    end
  end

  it "returns an early response without waiting for the remaining upload" do
    fixture = TunnelFixture.new
    socket = TCPSocket.new("127.0.0.1", fixture.server.port)
    socket.read_timeout = 3.seconds
    socket << "POST /early HTTP/1.1\r\nHost: #{fixture.hostname}\r\nContent-Length: 1000000\r\n\r\nab"
    socket.flush
    response = Tune::HTTPWire.head(socket)
    Tune::HTTPWire.status(response).should eq(413)
    Tune::HTTPWire::Body.new(socket, response.headers, response: true).gets_to_end.should eq("rejected")
    fixture.request.status_code.should eq(200)
  ensure
    socket.try &.close
    fixture.try &.close
  end

  it "forwards chunked uploads and preserves reserved application paths" do
    fixture = TunnelFixture.new
    socket = TCPSocket.new("127.0.0.1", fixture.server.port)
    socket.read_timeout = 3.seconds
    socket << "POST /echo HTTP/1.1\r\nHost: #{fixture.hostname}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
    socket.flush
    response = Tune::HTTPWire.head(socket)
    Tune::HTTPWire::Body.new(socket, response.headers, response: true).gets_to_end.should eq("abcde")
    fixture.request("GET", "/_tune/connect").body.should eq("GET /_tune/connect")
    fixture.request("GET", "/", extra: HTTP::Headers{"Upgrade" => "websocket", "Connection" => "Upgrade"}).status_code.should eq(501)
  ensure
    socket.try &.close
    fixture.try &.close
  end

  it "keeps a fast stream independent of a stalled response" do
    fixture = TunnelFixture.new
    completed = Channel(String).new(1)
    spawn { completed.send(fixture.request("GET", "/slow").body) }
    sleep 50.milliseconds
    fixture.request.body.should eq("GET /")
    fixture.gate.send(nil)
    select
    when response = completed.receive
      response.should eq("firstlast")
    when timeout(5.seconds)
      fail "Slow stream did not complete"
    end
  ensure
    fixture.try &.close
  end

  it "rejects oversized uploads and malformed framing without losing the tunnel" do
    fixture = TunnelFixture.new
    fixture.server.config.limits.max_request_body = 3_i64
    fixture.request("POST", "/echo", "four").status_code.should eq(413)
    socket = TCPSocket.new("127.0.0.1", fixture.server.port)
    socket.read_timeout = 3.seconds
    socket << "POST / HTTP/1.1\r\nHost: #{fixture.hostname}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n"
    socket.flush
    Tune::HTTPWire.status(Tune::HTTPWire.head(socket)).should eq(400)
    fixture.request.status_code.should eq(200)
  ensure
    socket.try &.close
    fixture.try &.close
  end

  it "reports an unavailable local service" do
    fixture = TunnelFixture.new
    fixture.app.close
    fixture.request.status_code.should eq(502)
  ensure
    fixture.try &.agent.stop
    fixture.try &.server.stop
  end

  it "reconnects with fresh registration after a broken tunnel" do
    fixture = TunnelFixture.new
    fixture.agent.stop
    reconnected = Channel(String).new(2)
    agent = Tune::Client::Agent.new(URI.parse("http://127.0.0.1:#{fixture.app_port}"), URI.parse(fixture.server.config.server.public_url), insecure_local: true)
    agent.on_connected { |url| reconnected.send(url) }
    spawn agent.run
    first = reconnected.receive
    fixture.server.registry.entries.each(&.close)
    select
    when second = reconnected.receive
      second.should_not eq(first)
    when timeout(5.seconds)
      fail "Client did not reconnect"
    end
  ensure
    agent.try &.stop
    fixture.try &.close
  end

  it "rejects unknown identities, missing keys and conflicting private names" do
    directory = File.join(Dir.tempdir, "tune-policy-#{Random::Secure.hex(8)}")
    path = File.join(directory, "owner")
    other_path = File.join(directory, "other")
    begin
      owner = Tune::Security::Identity.generate(path)
      other = Tune::Security::Identity.generate(other_path)
      fixture = TunnelFixture.new(owner, path + ".pub")
      target = URI.parse("http://127.0.0.1:#{fixture.app_port}")
      server = URI.parse(fixture.server.config.server.public_url)
      missing = Tune::Client::Agent.new(target, server, insecure_local: true)
      expect_raises(Tune::Client::FatalError) { missing.connect }
      unknown = Tune::Client::Agent.new(target, server, identity: other, insecure_local: true)
      expect_raises(Tune::Client::FatalError) { unknown.connect }
      named = Tune::Client::Agent.new(target, server, "raspberry", owner, true)
      named_session = named.connect
      spawn named_session.run
      conflict = Tune::Client::Agent.new(target, server, "raspberry", owner, true)
      expect_raises(Tune::Client::FatalError) { conflict.connect }
      File.open(path + ".pub", "a") { |file| file << File.read(other_path + ".pub") }
      fixture.server.reload
      named.stop
      deadline = Time.instant + 2.seconds
      while fixture.server.registry.find("raspberry") && Time.instant < deadline
        sleep 5.milliseconds
      end
      replacement = Tune::Client::Agent.new(target, server, "raspberry", other, true)
      replacement.connect
      replacement.public_url.not_nil!.should contain("raspberry.")
    ensure
      named.try &.stop
      replacement.try &.stop
      fixture.try &.close
      [path, path + ".pub", other_path, other_path + ".pub"].each { |file| File.delete(file) if File.exists?(file) }
      Dir.delete(directory) if Dir.exists?(directory)
    end
  end

  it "releases repeated interrupted uploads without exhausting flow-control credit" do
    fixture = TunnelFixture.new
    40.times do
      socket = TCPSocket.new("127.0.0.1", fixture.server.port)
      socket << "POST /echo HTTP/1.1\r\nHost: #{fixture.hostname}\r\nContent-Length: 1000000\r\n\r\n" << "x" * 8192
      socket.flush
      socket.close
      sleep 5.milliseconds
    end
    sleep 100.milliseconds
    fixture.request.body.should eq("GET /")
    fixture.server.registry.entries.first.session.not_nil!.streams.size.should eq(0)
  ensure
    fixture.try &.close
  end
end
