require "http"
require "openssl"

module Tune::HTTPWire
  MAX_HEADERS = 16_384
  TOKEN       = /\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/
  HOP         = %w(connection keep-alive proxy-authenticate proxy-authorization te trailer transfer-encoding upgrade)

  class Error < Exception
    getter status : Int32

    def initialize(message : String, @status = 400)
      super(message)
    end
  end

  record Head, first : String, headers : HTTP::Headers

  def self.line(io : IO, limit = MAX_HEADERS) : String
    line = io.gets('\n', limit + 1, chomp: false) || raise IO::EOFError.new
    raise HTTPWire::Error.new("HTTP line too large", 431) if line.bytesize > limit
    raise HTTPWire::Error.new("Expected CRLF") unless line.ends_with?("\r\n")
    line.byte_slice(0, line.bytesize - 2)
  end

  def self.head(io : IO, limit = MAX_HEADERS) : Head
    first = line(io, Math.min(limit, 8192))
    headers = HTTP::Headers.new
    remaining = limit - first.bytesize - 2
    loop do
      raise HTTPWire::Error.new("Headers too large", 431) if remaining < 2
      value = line(io, remaining)
      remaining -= value.bytesize + 2
      break if value.empty?
      pair = value.split(':', 2)
      raise HTTPWire::Error.new("Invalid header") unless pair.size == 2 && TOKEN.matches?(pair[0])
      field = pair[1].strip(" \t")
      raise HTTPWire::Error.new("Invalid header value") if field.each_byte.any? { |b| b == 127 || (b < 32 && b != 9) }
      headers.add(pair[0], field)
    end
    validate_framing(headers)
    Head.new(first, headers)
  end

  def self.validate_framing(headers : HTTP::Headers)
    lengths = headers.get?("Content-Length")
    encodings = headers.get?("Transfer-Encoding")
    raise HTTPWire::Error.new("Ambiguous HTTP framing") if lengths && encodings
    if lengths
      raise HTTPWire::Error.new("Repeated Content-Length") unless lengths.size == 1
      value = lengths[0]
      raise HTTPWire::Error.new("Invalid Content-Length") unless /\A[0-9]+\z/.matches?(value) && value.to_i64?
    end
    if encodings
      raise HTTPWire::Error.new("Unsupported Transfer-Encoding") unless encodings.size == 1 && encodings[0].downcase == "chunked"
    end
  end

  def self.request(head : Head) : {String, String}
    parts = head.first.split(' ')
    raise HTTPWire::Error.new("Invalid request line") unless parts.size == 3 && parts[2].in?("HTTP/1.0", "HTTP/1.1")
    method, path = parts[0], parts[1]
    raise HTTPWire::Error.new("CONNECT is unsupported", 501) if method == "CONNECT"
    raise HTTPWire::Error.new("Invalid request target") unless TOKEN.matches?(method) && path.starts_with?('/') && !path.starts_with?("//") && !path.includes?('#') && !path.each_byte.any? { |b| b <= 32 || b == 127 }
    {method, path}
  end

  def self.status(head : Head) : Int32
    parts = head.first.split(' ', 3)
    code = parts[1]?.try(&.to_i?)
    raise HTTPWire::Error.new("Invalid upstream status", 502) unless parts[0].in?("HTTP/1.0", "HTTP/1.1") && code && (100..599).includes?(code)
    code
  end

  def self.hostname(headers : HTTP::Headers) : String
    hosts = headers.get?("Host")
    raise HTTPWire::Error.new("Missing or repeated Host") unless hosts && hosts.size == 1
    host = hosts[0].downcase
    raise HTTPWire::Error.new("Invalid Host") unless /\A[a-z0-9.-]+(?::[0-9]{1,5})?\z/.matches?(host)
    host.split(':', 2)[0].rstrip('.')
  end

  def self.clean(headers : HTTP::Headers, forwarded = false) : HTTP::Headers
    result = headers.dup
    headers.get?("Connection").try &.each do |value|
      value.split(',').each { |name| result.delete(name.strip) }
    end
    HOP.each { |name| result.delete(name) }
    if forwarded
      result.to_a.map(&.[0]).each do |name|
        result.delete(name) if name.downcase.starts_with?("x-forwarded-") || name.downcase == "forwarded" || name.downcase == "x-real-ip"
      end
    end
    result
  end

  def self.write_head(io : IO, first : String, headers : HTTP::Headers)
    io << first << "\r\n"
    headers.each do |name, values|
      raise HTTPWire::Error.new("Invalid outgoing header") unless TOKEN.matches?(name)
      values.each do |value|
        raise HTTPWire::Error.new("Invalid outgoing header") if value.each_byte.any? { |b| b == 127 || (b < 32 && b != 9) }
        io << name << ": " << value << "\r\n"
      end
    end
    io << "\r\n"
    io.flush
  end

  def self.respond(io : IO, status : Int32, message : String = "")
    message = "#{HTTP::Status.new(status).description}\n" if message.empty?
    write_head(io, "HTTP/1.1 #{status} #{HTTP::Status.new(status).description}", HTTP::Headers{"Content-Length" => message.bytesize.to_s, "Content-Type" => "text/plain", "Connection" => "close"})
    io << message
    io.flush
  end

  def self.pack_headers(fields : Protocol::Fields, headers : HTTP::Headers)
    pairs = headers.to_a.flat_map { |key, values| values.map { |v| {key, v} } }
    fields.u32(pairs.size)
    pairs.each { |key, value| fields.string(key).string(value) }
  end

  def self.unpack_headers(fields : Protocol::Fields) : HTTP::Headers
    count = fields.u32
    raise Protocol::Error.new("Too many headers") if count > 1024
    headers = HTTP::Headers.new
    total = 0
    count.times do
      name, value = fields.string, fields.string
      total += name.bytesize + value.bytesize + 4
      raise Protocol::Error.new("Headers too large") if total > MAX_HEADERS
      raise Protocol::Error.new("Invalid header") unless TOKEN.matches?(name) && !value.each_byte.any? { |b| b == 127 || (b < 32 && b != 9) }
      headers.add(name, value)
    end
    validate_framing(headers)
    headers
  end

  class Body < IO
    getter total = 0_i64
    @remaining : Int64?
    @chunk_remaining = 0_i64
    @done = false
    @need_crlf = false

    def initialize(@io : IO, headers : HTTP::Headers, @limit : Int64 = Int64::MAX, response = false, prohibited = false)
      @chunked = headers["Transfer-Encoding"]?.try(&.downcase) == "chunked"
      @remaining = headers["Content-Length"]?.try(&.to_i64)
      @remaining = 0_i64 if prohibited || (!response && !@chunked && @remaining.nil?)
      @chunked = false if prohibited
      raise HTTPWire::Error.new("Request body too large", 413) if @remaining.try { |n| n > @limit }
    end

    def read(slice : Bytes) : Int32
      return 0 if @done || slice.empty?
      if @chunked
        if @chunk_remaining == 0
          if @need_crlf
            raise HTTPWire::Error.new("Invalid chunk delimiter") unless HTTPWire.line(@io, 2).empty?
          end
          size = HTTPWire.line(@io, 1024).split(';', 2)[0]
          raise HTTPWire::Error.new("Invalid chunk size") unless /\A[0-9a-fA-F]+\z/.matches?(size)
          @chunk_remaining = size.to_i64?(16) || raise HTTPWire::Error.new("Invalid chunk size")
          if @chunk_remaining == 0
            remaining = MAX_HEADERS
            loop do
              trailer = HTTPWire.line(@io, remaining)
              remaining -= trailer.bytesize + 2
              break if trailer.empty?
              raise HTTPWire::Error.new("Trailers too large") if remaining < 2
              name, separator, value = trailer.partition(':')
              raise HTTPWire::Error.new("Invalid trailer") if separator.empty? || !TOKEN.matches?(name) || name.downcase.in?("content-length", "transfer-encoding", "host") || value.each_byte.any? { |b| b < 32 && b != 9 }
            end
            @done = true
            return 0
          end
          @need_crlf = true
        end
        count = @io.read(slice[0, Math.min(slice.size.to_i64, @chunk_remaining).to_i])
        raise IO::EOFError.new if count == 0
        @chunk_remaining -= count
      elsif remaining = @remaining
        return 0 if remaining == 0
        count = @io.read(slice[0, Math.min(slice.size.to_i64, remaining).to_i])
        raise IO::EOFError.new if count == 0
        @remaining = remaining - count
      else
        count = @io.read(slice)
      end
      @total += count
      raise HTTPWire::Error.new("Request body too large", 413) if @total > @limit
      count
    end

    def write(slice : Bytes) : Nil
      raise IO::Error.new("Read-only body")
    end
  end

  def self.copy_body(source : IO, destination : IO, chunked = false)
    buffer = Bytes.new(Protocol::CHUNK)
    while (count = source.read(buffer)) > 0
      destination << count.to_s(16) << "\r\n" if chunked
      destination.write(buffer[0, count])
      destination << "\r\n" if chunked
      destination.flush
    end
    destination << "0\r\n\r\n" if chunked
    destination.flush
  end

  def self.connect(uri : URI) : IO
    host = uri.host || raise HTTPWire::Error.new("Missing hostname")
    tcp = TCPSocket.new(host, uri.port || (uri.scheme == "https" ? 443 : 80), connect_timeout: 10.seconds)
    tcp.read_timeout = 60.seconds
    tcp.write_timeout = 60.seconds
    if uri.scheme == "https"
      OpenSSL::SSL::Socket::Client.new(tcp, context: OpenSSL::SSL::Context::Client.new, sync_close: true, hostname: host)
    else
      tcp
    end
  rescue ex
    tcp.try &.close
    raise ex
  end
end
