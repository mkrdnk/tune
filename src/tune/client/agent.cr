module Tune::Client
  class FatalError < Exception
  end

  class RetryError < IO::Error
    getter delay : Time::Span

    def initialize(message : String, @delay : Time::Span)
      super(message)
    end
  end

  class Agent
    getter? stopped = false
    getter public_url : String?
    getter session : Protocol::Session?
    @ws : Protocol::WebSocket?
    @connected : Proc(String, Nil)?

    def initialize(@target : URI, @server : URI, @name = "", @identity : Security::Identity? = nil, @insecure_local = false)
      raise ArgumentError.new("Server must be an HTTP/HTTPS origin") unless @server.scheme.in?("https", "http") && @server.host && @server.path.in?("", "/") && !@server.user && !@server.password && !@server.query && !@server.fragment
      if @server.scheme == "http"
        host = @server.host.not_nil!
        loopback = host == "localhost" || Socket::IPAddress.new(host, 0).loopback?
        raise ArgumentError.new("HTTP requires --insecure-local and a loopback server") unless @insecure_local && loopback
        Tune::Log.warn { "Local development mode: tunnel traffic is not encrypted" }
      end
    end

    def on_connected(&@connected : String -> Nil)
    end

    def self.target(value : String) : URI
      value = "localhost:#{value}" if /\A[0-9]+\z/.matches?(value)
      value = "http://#{value}" unless value.includes?("://")
      uri = URI.parse(value)
      raise ArgumentError.new("TARGET must be a host, port, or HTTP/HTTPS origin") unless uri.scheme.in?("http", "https") && uri.host && !uri.host.not_nil!.empty? && uri.path.in?("", "/") && !uri.query && !uri.fragment && !uri.user && !uri.password && (!uri.port || (1..65_535).includes?(uri.port.not_nil!))
      uri
    end

    def connect : Protocol::Session
      io = HTTPWire.connect(@server)
      key = Base64.strict_encode(Random::Secure.random_bytes(16))
      host = @server.host.not_nil!
      host = "[#{host}]" if host.includes?(':')
      host += ":#{@server.port}" if @server.port
      headers = HTTP::Headers{"Host" => host, "Connection" => "Upgrade", "Upgrade" => "websocket", "Sec-WebSocket-Key" => key, "Sec-WebSocket-Version" => "13"}
      HTTPWire.write_head(io, "GET /_tune/connect HTTP/1.1", headers)
      head = HTTPWire.head(io)
      raise FatalError.new("Server rejected WebSocket connection (#{HTTPWire.status(head)})") unless HTTPWire.status(head) == 101
      raise FatalError.new("Invalid WebSocket handshake") unless head.headers["Sec-WebSocket-Accept"]? == HTTP::WebSocket::Protocol.key_challenge(key) && head.headers["Upgrade"]?.try(&.downcase) == "websocket" && head.headers.includes_word?("Connection", "Upgrade") && !head.headers.has_key?("Sec-WebSocket-Extensions")
      ws = Protocol::WebSocket.new(io, true)
      @ws = ws
      fingerprint = @identity.try(&.fingerprint) || ""
      url = @server.to_s.rstrip('/')
      ws.send(Protocol::Frame.new(:hello, 0_u32, Protocol::Fields.new.string(Protocol::VERSION).string(@name).string(fingerprint).string(url).bytes))
      authenticated = false
      deadline = Time.instant + 240.seconds
      loop do
        raise FatalError.new("Tunnel setup timed out") if Time.instant > deadline
        frame = ws.receive
        raise FatalError.new("Invalid handshake stream") unless frame.stream_id == 0
        case frame.type
        when .challenge?
          raise FatalError.new("Invalid authentication challenge") if authenticated || frame.payload.size != 32
          identity = @identity || raise FatalError.new("Private server requires an identity; run tune keygen")
          transcript = Security::Challenge.transcript(url, fingerprint, @name, frame.payload)
          ws.send(Protocol::Frame.new(:auth, 0_u32, identity.key.sign(transcript)))
          authenticated = true
        when .ping?
          raise FatalError.new("Invalid setup heartbeat") unless frame.payload.size == 8
          ws.send(Protocol::Frame.new(:pong, 0_u32, frame.payload))
        when .welcome?
          fields = Protocol::Fields.new(frame.payload)
          @public_url = fields.string(4096)
          max_streams = fields.u32.to_i
          fields.finish
          raise FatalError.new("Invalid stream limit") unless (1..1024).includes?(max_streams)
          session = Protocol::Session.new(ws, false, max_streams)
          proxy = Proxy.new(@target)
          session.on_open { |stream, payload| proxy.handle(stream, payload) }
          @session = session
          @connected.try &.call(@public_url.not_nil!)
          return session
        when .error?
          fields = Protocol::Fields.new(frame.payload)
          message = fields.string
          retry_seconds = fields.u32
          fields.finish
          raise RetryError.new(message, retry_seconds.seconds) if retry_seconds > 0
          raise FatalError.new(message)
        else
          raise FatalError.new("Invalid handshake sequence")
        end
      end
    rescue ex
      io.try &.close
      raise ex
    end

    def run
      delay = 1.0
      until stopped?
        started = Time.instant
        minimum_wait = 0.seconds
        begin
          connect.run
          delay = 1.0 if Time.instant - started > 60.seconds
        rescue ex : RetryError
          minimum_wait = ex.delay
          Tune::Log.warn { ex.message }
        rescue ex : FatalError | OpenSSL::SSL::Error
          raise ex unless stopped?
        rescue ex : IO::Error | Socket::Error
          Tune::Log.debug { "Connection lost: #{ex.class}" }
        end
        break if stopped?
        wait = Math.max(delay * (0.5 + Random::Secure.rand * 0.5), minimum_wait.total_seconds)
        Tune::Log.info { "Reconnecting in #{wait.round(1)} seconds" }
        deadline = Time.instant + wait.seconds
        while !stopped? && Time.instant < deadline
          sleep 100.milliseconds
        end
        delay = Math.min(delay * 2, 30.0)
      end
    ensure
      stop
    end

    def stop
      @stopped = true
      @session.try &.close
      @ws.try &.close
    end
  end
end
