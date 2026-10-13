require "set"

module Tune::Server
  class Server
    getter config : Config
    getter registry = Registry.new
    getter port : Int32
    getter? stopped = false
    @listener : TCPServer
    @connections = Set(TCPSocket).new
    @authorized : Security::AuthorizedKeys?
    @attempts = {} of String => {Bucket, Time::Instant}
    @certificates : TLS::Manager?
    @challenge_listener : TCPServer?
    @shutdown_done = Channel(Nil).new

    def initialize(@config : Config)
      config.validate
      @authorized = Security::AuthorizedKeys.new(config.auth.authorized_keys) if config.auth.mode == "private"
      @listener = TCPServer.new(config.server.bind, config.server.port)
      @port = @listener.local_address.port
    end

    def run
      if config.tls.mode == "acme"
        manager = TLS::Manager.new(config.tls.acme)
        @certificates = manager
        @challenge_listener = challenge = TCPServer.new(config.server.bind, config.tls.acme.http_port)
        spawn challenges(challenge, manager)
        manager.ensure_certificate(config.server.domain)
        spawn renew_certificates(manager)
      end
      Tune::Log.info { "Listening on #{config.server.bind}:#{port} (#{config.auth.mode}, #{config.tls.mode})" }
      while socket = @listener.accept?
        if @connections.size >= config.limits.max_connections
          socket.close
          next
        end
        @connections << socket
        spawn handle(socket)
      end
    ensure
      stop
    end

    private def handle(socket : TCPSocket)
      io = socket.as(IO)
      upgraded = false
      responded = false
      socket.read_timeout = 10.seconds
      socket.write_timeout = 60.seconds
      if manager = @certificates
        context = manager.context(config.server.domain)
        io = OpenSSL::SSL::Socket::Server.new(socket, context, sync_close: true)
      end
      head = HTTPWire.head(io, config.limits.max_header_size)
      raise HTTPWire::Error.new("Server shutting down", 503) if stopped?
      method, path = HTTPWire.request(head)
      hostname = HTTPWire.hostname(head.headers)
      if io.is_a?(OpenSSL::SSL::Socket::Server)
        raise HTTPWire::Error.new("SNI and Host differ", 421) unless io.hostname.try(&.downcase) == hostname
      end
      socket.read_timeout = 60.seconds
      if hostname == config.server.domain
        if path == "/_tune/connect" && method == "GET"
          upgrade(io, head)
          upgraded = true
          control(Protocol::WebSocket.new(io, false), socket, forwarded_client(head.headers, socket.remote_address.address))
        else
          HTTPWire.respond(io, 404)
        end
      else
        responded = true
        ingress(io, head, hostname, method, path, socket.remote_address.address)
      end
    rescue ex : HTTPWire::Error
      HTTPWire.respond(io, ex.status) if io && !upgraded && !responded
    rescue ex : IO::Error | OpenSSL::SSL::Error
      Tune::Log.debug { "Connection closed: #{ex.class}" }
    rescue ex
      Tune::Log.error { "Connection error: #{ex.class}: #{ex.message}" }
    ensure
      io.try &.close
      @connections.delete(socket)
    end

    private def upgrade(io : IO, head : HTTPWire::Head)
      headers = head.headers
      raise HTTPWire::Error.new("WebSocket Upgrade required", 426) unless headers["Upgrade"]?.try(&.downcase) == "websocket" && headers.includes_word?("Connection", "Upgrade") && headers["Sec-WebSocket-Version"]? == "13"
      raise HTTPWire::Error.new("Upgrade body is forbidden") if headers.has_key?("Transfer-Encoding") || headers["Content-Length"]?.try { |v| v != "0" }
      key = headers["Sec-WebSocket-Key"]? || raise HTTPWire::Error.new("Missing WebSocket key")
      begin
        raise HTTPWire::Error.new("Invalid WebSocket key") unless Base64.decode(key).size == 16
      rescue ArgumentError
        raise HTTPWire::Error.new("Invalid WebSocket key")
      end
      HTTPWire.write_head(io, "HTTP/1.1 101 Switching Protocols", HTTP::Headers{"Connection" => "Upgrade", "Upgrade" => "websocket", "Sec-WebSocket-Accept" => HTTP::WebSocket::Protocol.key_challenge(key)})
    end

    private def control(ws : Protocol::WebSocket, socket : TCPSocket, ip : String)
      entry : Entry? = nil
      socket.read_timeout = 30.seconds
      raise Protocol::StreamError.new("Connection rate limit exceeded", 429) unless allow_connection?(ip)
      frame = ws.receive
      raise Protocol::Error.new("Expected HELLO") unless frame.type.hello? && frame.stream_id == 0
      fields = Protocol::Fields.new(frame.payload)
      version, name, fingerprint, url = fields.string(32), fields.string(63), fields.string(128), fields.string(4096)
      fields.finish
      raise ArgumentError.new("Unsupported protocol version") unless version == Protocol::VERSION
      raise ArgumentError.new("Server URL does not match public_url") unless url == config.server.public_url.rstrip('/')
      if config.auth.mode == "private"
        challenge = Security::Challenge.new(url, fingerprint, name)
        ws.send(Protocol::Frame.new(:challenge, 0_u32, challenge.nonce))
        auth = ws.receive
        valid = auth.type.auth? && auth.stream_id == 0 && challenge.verify(@authorized.try(&.keys[fingerprint]?), auth.payload)
        unless valid
          Tune::Log.warn { "Authentication failed" }
          raise ArgumentError.new("Authentication failed")
        end
        Tune::Log.info { "Authenticated #{fingerprint}" }
      else
        raise ArgumentError.new("Anonymous access is disabled") unless config.auth.allow_anonymous
        fingerprint = ""
      end
      entry = registry.reserve(name, fingerprint, ws, config)
      hostname = "#{entry.name}.#{config.server.domain}"
      if manager = @certificates
        provision(ws, manager, hostname)
      end
      raise ArgumentError.new("Authentication failed") if config.auth.mode == "private" && !@authorized.try(&.keys.has_key?(fingerprint))
      raise ArgumentError.new("Tunnel disabled") if config.tunnels.blocked_names.includes?(entry.name) || (config.auth.mode == "public" && !config.auth.allow_anonymous)
      base = URI.parse(config.server.public_url)
      base.host = hostname
      base.path = ""
      session = Protocol::Session.new(ws, true, config.tunnels.max_streams_per_session)
      entry.session = session
      ws.send(Protocol::Frame.new(:welcome, 0_u32, Protocol::Fields.new.string(base.to_s).u32(config.tunnels.max_streams_per_session).bytes))
      Tune::Log.info { "Tunnel created: #{hostname}" }
      socket.read_timeout = 60.seconds
      session.run
    rescue ex
      Tune::Log.debug { "Control connection rejected: #{ex.class}: #{ex.message}" }
      unless ws.closed?
        begin
          retry_seconds = 0
          if ex.is_a?(TLS::ACMEError)
            retry_seconds = ex.retry_at.try { |time| Math.max((time - Time.utc).total_seconds.ceil.to_i64, 1_i64).clamp(1_i64, UInt32::MAX.to_i64).to_u32 } || 900_u32
          elsif ex.is_a?(Protocol::StreamError) && ex.status.in?(429, 503)
            retry_seconds = 30
          end
          ws.send(Protocol::Frame.new(:error, 0_u32, Protocol::Fields.new.string(ex.message || "Connection failed").u32(retry_seconds).bytes))
        rescue IO::Error
          Tune::Log.debug { "Peer disconnected before error delivery" }
        end
      end
    ensure
      if entry
        registry.remove(entry)
        Tune::Log.info { "Tunnel closed: #{entry.name}" }
      end
      ws.close
    end

    private def allow_connection?(ip : String) : Bool
      now = Time.instant
      @attempts.reject! { |_, value| now - value[1] > 5.minutes }
      return false if @attempts.size >= 4096 && !@attempts.has_key?(ip)
      bucket = @attempts[ip]?.try(&.[0]) || Bucket.new(config.limits.connections_per_minute / 60.0, config.limits.connections_per_minute.to_f)
      @attempts[ip] = {bucket, now}
      bucket.take
    end

    private def ingress(io : IO, head : HTTPWire::Head, hostname : String, method : String, path : String, peer : String)
      sent = false
      stream : Protocol::Stream? = nil
      entry : Entry? = nil
      begin
        suffix = ".#{config.server.domain}"
        raise HTTPWire::Error.new("Unknown tunnel", 404) unless hostname.ends_with?(suffix)
        name = hostname[0, hostname.size - suffix.size]
        raise HTTPWire::Error.new("Unknown tunnel", 404) unless Config.valid_name?(name)
        entry = registry.find(name) || raise HTTPWire::Error.new("Unknown tunnel", 404)
        session = entry.session || raise HTTPWire::Error.new("Tunnel pending", 503)
        raise HTTPWire::Error.new("Upgrade is unsupported", 501) if head.headers.has_key?("Upgrade")
        raise HTTPWire::Error.new("Rate limit exceeded", 429) unless entry.requests.take
        body = HTTPWire::Body.new(io, head.headers, config.limits.max_request_body)
        headers = HTTPWire.clean(head.headers, forwarded: true)
        headers["Content-Length"] = "0" unless head.headers.has_key?("Content-Length") || head.headers.has_key?("Transfer-Encoding")
        client_ip = forwarded_client(head.headers, peer)
        scheme = URI.parse(config.server.public_url).scheme.not_nil!
        if config.server.trusted_proxies.includes?(peer)
          if proto = head.headers["X-Forwarded-Proto"]?
            raise HTTPWire::Error.new("Invalid forwarded scheme") unless proto.in?("http", "https")
            scheme = proto
          end
        end
        headers["X-Forwarded-For"] = client_ip
        headers["X-Forwarded-Proto"] = scheme
        headers["X-Forwarded-Host"] = head.headers["Host"]
        fields = Protocol::Fields.new.string(method).string(path)
        HTTPWire.pack_headers(fields, headers)
        stream = session.open(fields.bytes)
        active = stream
        tunnel = entry
        if expect = head.headers["Expect"]?
          raise HTTPWire::Error.new("Unsupported expectation", 417) unless expect.downcase == "100-continue"
          io << "HTTP/1.1 100 Continue\r\n\r\n"
          io.flush
        end
        spawn do
          begin
            buffer = Bytes.new(Protocol::CHUNK)
            while !active.send_closed? && (count = body.read(buffer)) > 0
              tunnel.upload.pace(count) { active.check; active.send_closed? }
              active.write(buffer[0, count])
            end
            active.finish
          rescue ex : HTTPWire::Error
            active.fail(Protocol::StreamError.new(ex.message || "Upload failed", ex.status))
            session.reset(active, ex.status) unless session.closed?
          rescue ex : IO::Error
            unless active.send_closed? || session.closed?
              session.reset(active, 502)
            end
          end
        end
        response = Protocol::Fields.new(stream.await_headers)
        status = response.u32.to_i
        raise Protocol::Error.new("Invalid response status") unless (200..599).includes?(status)
        response_headers = HTTPWire.clean(HTTPWire.unpack_headers(response))
        response.finish
        response_headers["Connection"] = "close"
        prohibited = method == "HEAD" || status.in?(204, 304)
        response_headers.delete("Content-Length") if status == 204
        chunked = !prohibited && !response_headers.has_key?("Content-Length")
        response_headers["Transfer-Encoding"] = "chunked" if chunked
        HTTPWire.write_head(io, "HTTP/1.1 #{status} #{HTTP::Status.new(status).description}", response_headers)
        sent = true
        buffer = Bytes.new(Protocol::CHUNK)
        total = 0_i64
        expected = response_headers["Content-Length"]?.try(&.to_i64)
        while (count = stream.read(buffer)) > 0
          raise Protocol::Error.new("Body forbidden for response") if prohibited
          total += count
          raise Protocol::Error.new("Response length mismatch") if expected && total > expected
          entry.download.pace(count) { stream.check; false }
          io << count.to_s(16) << "\r\n" if chunked
          io.write(buffer[0, count])
          io << "\r\n" if chunked
          io.flush
        end
        raise Protocol::Error.new("Response length mismatch") if !prohibited && expected && expected != total
        io << "0\r\n\r\n" if chunked
        io.flush
      rescue ex : HTTPWire::Error
        HTTPWire.respond(io, ex.status) unless sent
      rescue ex : Protocol::StreamError
        HTTPWire.respond(io, ex.status) unless sent
      rescue ex : IO::TimeoutError
        HTTPWire.respond(io, 504) unless sent
      rescue ex
        Tune::Log.debug { "Ingress failed: #{ex.class}" }
        HTTPWire.respond(io, 502) unless sent
      ensure
        if stream
          begin
            stream.session.reset(stream, 502) unless stream.session.closed? || (stream.send_closed? && stream.recv_closed?)
          ensure
            stream.session.remove(stream)
          end
        end
      end
    end

    def reload(updated : Config = config)
      begin
        updated.validate
        keys = updated.auth.mode == "private" ? Security::AuthorizedKeys.new(updated.auth.authorized_keys) : nil
        @authorized = keys
        config.auth = updated.auth
        config.tunnels.blocked_names = updated.tunnels.blocked_names
        registry.entries.each do |entry|
          allowed = updated.auth.mode == "private" ? !!keys.try(&.keys.has_key?(entry.fingerprint)) : updated.auth.allow_anonymous
          entry.close unless allowed && !updated.tunnels.blocked_names.includes?(entry.name)
        end
        Tune::Log.info { "Access policy reloaded" }
      rescue ex
        if config.auth.mode == "private"
          @authorized = nil
          registry.entries.each(&.close)
        end
        Tune::Log.error { "Access reload failed; private access closed: #{ex.class}" }
      end
    end

    private def forwarded_client(headers : HTTP::Headers, peer : String) : String
      return peer unless config.server.trusted_proxies.includes?(peer)
      value = headers["X-Forwarded-For"]?
      return peer unless value
      addresses = value.split(',').map(&.strip)
      addresses.each { |address| Socket::IPAddress.new(address, 0) }
      addresses << peer
      while addresses.size > 1 && config.server.trusted_proxies.includes?(addresses.last)
        addresses.pop
      end
      addresses.last
    rescue Socket::Error | ArgumentError
      raise HTTPWire::Error.new("Invalid forwarded address")
    end

    def stop(grace = false)
      if stopped?
        @shutdown_done.receive?
        return
      end
      @stopped = true
      @listener.close
      @challenge_listener.try &.close
      if grace
        deadline = Time.instant + 10.seconds
        while registry.entries.any? { |entry| entry.session.try { |session| !session.streams.empty? } } && Time.instant < deadline
          sleep 50.milliseconds
        end
      end
      registry.entries.each(&.close)
      @connections.to_a.each(&.close)
      @certificates.try &.close
      Tune::Log.info { "Server stopped" }
    ensure
      @shutdown_done.close unless @shutdown_done.closed?
    end

    private def provision(ws : Protocol::WebSocket, manager : TLS::Manager, hostname : String)
      result = Channel(Exception?).new(1)
      spawn do
        begin
          manager.ensure_certificate(hostname)
          result.send(nil)
        rescue ex
          result.send(ex)
        end
      end
      deadline = Time.instant + 180.seconds
      loop do
        raise ArgumentError.new("Certificate provisioning timed out") if Time.instant > deadline
        select
        when error = result.receive
          raise error if error
          return
        when timeout(15.seconds)
          token = Random::Secure.random_bytes(8)
          ws.send(Protocol::Frame.new(:ping, 0_u32, token))
          pong = ws.receive
          raise Protocol::Error.new("Invalid setup heartbeat") unless pong.type.pong? && pong.stream_id == 0 && pong.payload == token
        end
      end
    end

    private def challenges(listener : TCPServer, manager : TLS::Manager)
      while socket = listener.accept?
        if @connections.size >= config.limits.max_connections
          socket.close
          next
        end
        @connections << socket
        spawn handle_challenge(socket, manager)
      end
    end

    private def handle_challenge(socket : TCPSocket, manager : TLS::Manager)
      socket.read_timeout = 10.seconds
      socket.write_timeout = 10.seconds
      head = HTTPWire.head(socket)
      method, path = HTTPWire.request(head)
      hostname = HTTPWire.hostname(head.headers)
      if method == "GET" && (answer = manager.challenge(hostname, path))
        HTTPWire.respond(socket, 200, answer)
      elsif !path.starts_with?("/.well-known/acme-challenge/") && manager.available?(hostname)
        base = URI.parse(config.server.public_url)
        base.host = hostname
        HTTPWire.write_head(socket, "HTTP/1.1 308 Permanent Redirect", HTTP::Headers{"Location" => base.to_s.rstrip('/') + path, "Content-Length" => "0", "Connection" => "close"})
      else
        HTTPWire.respond(socket, 404)
      end
    rescue ex : Exception
      Tune::Log.debug { "HTTP challenge connection failed: #{ex.class}" }
    ensure
      socket.close
      @connections.delete(socket)
    end

    private def renew_certificates(manager : TLS::Manager)
      until stopped?
        60.times do
          break if stopped?
          sleep 1.second
        end
        break if stopped?
        names = [config.server.domain] + registry.entries.map { |entry| "#{entry.name}.#{config.server.domain}" }
        names.each do |name|
          break if stopped?
          begin
            manager.ensure_certificate(name)
          rescue ex
            Tune::Log.error { "Certificate renewal failed for #{name}: #{ex.message}" }
          end
        end
      end
    end
  end
end
