module Tune::Client
  class Proxy
    def initialize(@target : URI)
    end

    def handle(stream : Protocol::Stream, payload : Bytes)
      spawn do
        begin
          stream.check
          fields = Protocol::Fields.new(payload)
          method, path = fields.string(32), fields.string(8192)
          headers = HTTPWire.unpack_headers(fields)
          fields.finish
          HTTPWire.request(HTTPWire::Head.new("#{method} #{path} HTTP/1.1", headers))
          headers = HTTPWire.clean(headers)
          host = @target.host.not_nil!
          host = "[#{host}]" if host.includes?(':')
          headers["Host"] = @target.port ? "#{host}:#{@target.port}" : host
          headers["Connection"] = "close"
          headers.delete("Expect")
          length = headers["Content-Length"]?.try(&.to_i64)
          headers["Transfer-Encoding"] = "chunked" unless length
          io = HTTPWire.connect(@target)
          upstream = io
          stream.on_cancel { upstream.close }
          HTTPWire.write_head(io, "#{method} #{path} HTTP/1.1", headers)
          upload_finished = false
          spawn do
            begin
              copy_request(stream, upstream, length)
              upload_finished = true
            rescue ex : IO::Error | HTTPWire::Error
              unless stream.recv_closed?
                stream.session.reset(stream, 502)
                upstream.close
              end
            end
          end
          head = HTTPWire.head(io)
          status = HTTPWire.status(head)
          interim = 0
          while status < 200 && status != 101
            interim += 1
            raise HTTPWire::Error.new("Too many informational responses", 502) if interim > 16
            head = HTTPWire.head(io)
            status = HTTPWire.status(head)
          end
          raise HTTPWire::Error.new("Upstream Upgrade is unsupported", 502) if status == 101
          outgoing = HTTPWire.clean(head.headers)
          response = Protocol::Fields.new.u32(status)
          HTTPWire.pack_headers(response, outgoing)
          stream.session.send(Protocol::Frame.new(:headers, stream.id, response.bytes))
          prohibited = method == "HEAD" || status.in?(204, 304)
          body = HTTPWire::Body.new(io, head.headers, response: true, prohibited: prohibited)
          HTTPWire.copy_body(body, stream)
          unless upload_finished || stream.recv_closed?
            stream.session.reset(stream, 502, 1)
          end
          stream.finish
        rescue ex : IO::TimeoutError
          stream.session.reset(stream, 504) unless stream.session.closed?
        rescue ex : Exception
          Tune::Log.debug { "Local service request failed: #{ex.class}" }
          stream.session.reset(stream, 502) unless stream.session.closed?
        ensure
          io.try &.close
          stream.session.remove(stream)
        end
      end
    end

    private def copy_request(stream : Protocol::Stream, io : IO, length : Int64?)
      buffer = Bytes.new(Protocol::CHUNK)
      total = 0_i64
      while (count = stream.read(buffer)) > 0
        total += count
        raise HTTPWire::Error.new("Request length mismatch") if length && total > length
        io << count.to_s(16) << "\r\n" unless length
        io.write(buffer[0, count])
        io << "\r\n" unless length
        io.flush
      end
      raise HTTPWire::Error.new("Request length mismatch") if length && total != length
      io << "0\r\n\r\n" unless length
      io.flush
    end
  end
end
