require "deque"

module Tune::Protocol
  class StreamError < IO::Error
    getter status : Int32

    def initialize(message = "Stream cancelled", @status = 502)
      super(message)
    end
  end

  class Stream < IO
    getter id : UInt32
    getter session : Session
    getter buffered = 0
    getter? send_closed = false
    getter? recv_closed = false
    getter? recv_cancelled = false
    property send_credit = STREAM_WINDOW
    property recv_credit = STREAM_WINDOW
    @chunks = Deque(Bytes).new
    @wake = Channel(Nil).new(1)
    @header = Channel(Bytes).new(1)
    @offset = 0
    @failure : StreamError?
    @on_cancel : Proc(Nil)?
    @header_seen = false
    @last_progress = Time.instant

    def initialize(@session : Session, @id : UInt32)
    end

    def check
      if failure = @failure
        raise failure
      end
    end

    def on_cancel(&callback : -> Nil)
      @on_cancel = callback
      callback.call if @failure
    end

    def headers(payload : Bytes)
      raise Protocol::Error.new("Duplicate response headers") if @header_seen
      @header_seen = true
      @header.send(payload)
    end

    def await_headers : Bytes
      if failure = @failure
        raise failure
      end
      select
      when value = @header.receive
        value
      when timeout(60.seconds)
        raise StreamError.new("Response headers timeout", 504)
      end
    rescue Channel::ClosedError
      raise @failure || StreamError.new
    end

    def receive(data : Bytes)
      raise Protocol::Error.new("DATA before HEADERS") if @session.server? && !@header_seen
      raise Protocol::Error.new("DATA after END") if @recv_closed
      raise Protocol::Error.new("Invalid DATA size") if data.empty? || data.size > CHUNK || data.size > @recv_credit
      @recv_credit -= data.size
      @buffered += data.size
      @chunks << data
      signal
    end

    def end_receive
      raise Protocol::Error.new("Duplicate END") if @recv_closed
      raise Protocol::Error.new("END before HEADERS") if session.server? && !@header_seen
      @recv_closed = true
      signal
    end

    def read(slice : Bytes) : Int32
      return 0 if slice.empty?
      loop do
        if failure = @failure
          raise failure
        end
        if chunk = @chunks.first?
          count = Math.min(slice.size, chunk.size - @offset)
          slice.copy_from(chunk[@offset, count])
          @offset += count
          @buffered -= count
          if @offset == chunk.size
            @chunks.shift
            @offset = 0
          end
          @last_progress = Time.instant
          @recv_credit += count
          session.consumed(self, count)
          return count
        end
        return 0 if @recv_closed
        select
        when @wake.receive
        when timeout(60.seconds)
          raise StreamError.new("Stream read timeout", 504)
        end
      end
    end

    def write(slice : Bytes) : Nil
      offset = 0
      while offset < slice.size
        raise StreamError.new if @send_closed
        if failure = @failure
          raise failure
        end
        count = Math.min(CHUNK, slice.size - offset)
        count = session.reserve(self, count)
        if count == 0
          raise StreamError.new("Stream write timeout", 504) if Time.instant - @last_progress > 60.seconds
          sleep 2.milliseconds
          next
        end
        session.send(Frame.new(:data, id, slice[offset, count].dup))
        @last_progress = Time.instant
        offset += count
      end
    end

    def finish
      return if @send_closed
      @send_closed = true
      session.send(Frame.new(:end, id))
    end

    def stop_send
      @send_closed = true
    end

    def cancel_receive
      return if @recv_closed && @buffered == 0
      @recv_closed = true
      @recv_cancelled = true
      discard
      signal
    end

    def fail(error : StreamError)
      return if @failure
      @failure = error
      @send_closed = true
      @recv_closed = true
      @recv_cancelled = true
      discard
      @header.close unless @header.closed?
      signal
      begin
        @on_cancel.try &.call
      rescue IO::Error
        Tune::Log.debug { "Upstream already closed during cancellation" }
      end
    end

    private def discard
      count = @buffered
      @chunks.clear
      @buffered = 0
      @offset = 0
      session.discarded(count) if count > 0
    end

    def signal
      select
      when @wake.send(nil)
      else
      end
    end
  end

  class Session
    getter? server : Bool
    getter? closed = false
    getter streams = {} of UInt32 => Stream
    getter ws : WebSocket
    @controls = Channel(Frame).new(128)
    @data = Channel(Frame).new(64)
    @next_id = 1_u32
    @last_open_id = 0_u32
    @send_credit = SESSION_WINDOW
    @recv_credit = SESSION_WINDOW
    @last_pong = Time.instant
    @pending_ping : Bytes?
    @shutdown = Channel(Nil).new
    @on_open : Proc(Stream, Bytes, Nil)?

    def initialize(@ws : WebSocket, @server : Bool, @max_streams = 32)
    end

    def on_open(&@on_open : Stream, Bytes -> Nil)
    end

    def open(payload : Bytes) : Stream
      raise StreamError.new("Tunnel unavailable", 503) if closed?
      raise StreamError.new("Too many streams", 429) if streams.size >= @max_streams
      raise StreamError.new("Stream IDs exhausted", 503) if @next_id == UInt32::MAX
      id = @next_id
      @next_id += 1
      stream = Stream.new(self, id)
      streams[id] = stream
      send(Frame.new(:open, id, payload))
      stream
    end

    def send(frame : Frame)
      raise StreamError.new("Tunnel unavailable", 503) if closed?
      channel = frame.type.data? ? @data : @controls
      # END must stay behind all DATA already enqueued for that direction.
      channel = @data if frame.type.end?
      select
      when channel.send(frame)
      when timeout(10.seconds)
        close
        raise StreamError.new("Tunnel writer stalled", 503)
      end
    rescue Channel::ClosedError
      raise StreamError.new("Tunnel unavailable", 503)
    end

    def reserve(stream : Stream, requested : Int32) : Int32
      count = Math.min(requested, Math.min(stream.send_credit, @send_credit))
      stream.send_credit -= count
      @send_credit -= count
      count
    end

    def consumed(stream : Stream, count : Int32)
      @recv_credit += count
      return if closed?
      send(Frame.new(:window_update, stream.id, Fields.new.u32(count).bytes))
      send(Frame.new(:window_update, 0_u32, Fields.new.u32(count).bytes))
    end

    def discarded(count : Int32)
      @recv_credit += count
      send(Frame.new(:window_update, 0_u32, Fields.new.u32(count).bytes)) unless closed?
    end

    def reset(stream : Stream, status = 502, direction = 3)
      send(Frame.new(:reset, stream.id, Fields.new.u32(direction).u32(status).bytes)) unless closed?
      apply_reset(stream, direction, status)
    end

    def remove(stream : Stream)
      # Cancellation may leave in-flight DATA; IDs remain retired, never reused.
      streams.delete(stream.id)
      stream.fail(StreamError.new("Stream finished"))
    end

    def run
      spawn writer
      spawn heartbeat
      until closed?
        dispatch(ws.receive)
      end
    rescue ex : Error
      Tune::Log.warn { "Protocol error: #{ex.message}" }
      begin
        ws.send(Frame.new(:error, 0_u32, Fields.new.string(ex.message || "Protocol error").u32(0).bytes)) unless ws.closed?
      rescue IO::Error
        Tune::Log.debug { "Peer disconnected before protocol error delivery" }
      end
      close
    rescue ex : IO::Error | Channel::ClosedError
      Tune::Log.debug { "Tunnel disconnected: #{ex.class}" }
    ensure
      close
    end

    private def writer
      until closed?
        frame = select
        when control = @controls.receive
          control
        else
          select
          when control = @controls.receive
            control
          when data = @data.receive
            data
          end
        end
        ws.send(frame)
      end
    rescue ex : IO::Error | Channel::ClosedError
      close
    end

    private def heartbeat
      until closed?
        select
        when @shutdown.receive?
          break
        when timeout(15.seconds)
        end
        break if closed?
        if Time.instant - @last_pong > 45.seconds
          close
          break
        end
        unless @pending_ping
          @pending_ping = Random::Secure.random_bytes(8)
          send(Frame.new(:ping, 0_u32, @pending_ping.not_nil!))
        end
      end
    rescue IO::Error
      close
    end

    private def dispatch(frame : Frame)
      if frame.stream_id == 0
        case frame.type
        when .ping?
          raise Protocol::Error.new("Invalid PING") unless frame.payload.size == 8
          send(Frame.new(:pong, 0_u32, frame.payload))
        when .pong?
          raise Protocol::Error.new("Unexpected PONG") unless @pending_ping == frame.payload
          @pending_ping = nil
          @last_pong = Time.instant
        when .window_update?
          increment = window(frame)
          raise Protocol::Error.new("Connection window overflow") if @send_credit.to_i64 + increment > SESSION_WINDOW
          @send_credit += increment
        when .error?
          raise Protocol::Error.new("Peer reported a protocol error")
        else
          raise Protocol::Error.new("Invalid session message")
        end
        return
      end

      if frame.type.open?
        raise Protocol::Error.new("Invalid OPEN") if @server || frame.stream_id <= @last_open_id || streams.size >= @max_streams
        @last_open_id = frame.stream_id
        stream = Stream.new(self, frame.stream_id)
        streams[stream.id] = stream
        callback = @on_open || raise Protocol::Error.new("No OPEN handler")
        callback.call(stream, frame.payload)
        return
      end
      unless stream = streams[frame.stream_id]?
        highest = @server ? @next_id - 1 : @last_open_id
        raise Protocol::Error.new("Unknown stream ID") if frame.stream_id > highest
        if frame.type.data?
          raise Protocol::Error.new("Invalid retired DATA") if frame.payload.empty? || frame.payload.size > CHUNK || frame.payload.size > @recv_credit
          send(Frame.new(:window_update, 0_u32, Fields.new.u32(frame.payload.size).bytes))
        elsif !frame.type.in?(Type::End, Type::Reset, Type::WindowUpdate, Type::Headers)
          raise Protocol::Error.new("Invalid retired frame")
        end
        return
      end
      case frame.type
      when .headers?
        raise Protocol::Error.new("Client received HEADERS") unless @server
        stream.headers(frame.payload)
      when .data?
        raise Protocol::Error.new("Invalid DATA size") if frame.payload.empty? || frame.payload.size > CHUNK
        raise Protocol::Error.new("Connection window exceeded") if frame.payload.size > @recv_credit
        @recv_credit -= frame.payload.size
        if stream.recv_closed?
          raise Protocol::Error.new("DATA after END") unless stream.recv_cancelled?
          @recv_credit += frame.payload.size
          send(Frame.new(:window_update, 0_u32, Fields.new.u32(frame.payload.size).bytes))
        else
          stream.receive(frame.payload)
        end
      when .end?
        raise Protocol::Error.new("END has payload") unless frame.payload.empty?
        stream.end_receive unless stream.recv_cancelled?
      when .window_update?
        increment = window(frame)
        raise Protocol::Error.new("Stream window overflow") if stream.send_credit.to_i64 + increment > STREAM_WINDOW
        stream.send_credit += increment
      when .reset?
        fields = Fields.new(frame.payload)
        direction, status = fields.u32.to_i, fields.u32.to_i
        fields.finish
        raise Protocol::Error.new("Invalid RESET") unless (1..3).includes?(direction) && (400..599).includes?(status)
        apply_reset(stream, direction, status)
      else
        raise Protocol::Error.new("Invalid stream message")
      end
    end

    private def window(frame : Frame) : Int32
      fields = Fields.new(frame.payload)
      amount = fields.u32
      fields.finish
      raise Protocol::Error.new("Invalid window increment") if amount == 0 || amount > SESSION_WINDOW
      amount.to_i
    end

    private def apply_reset(stream : Stream, direction : Int32, status : Int32)
      if direction == 3
        stream.fail(StreamError.new("Remote stream error", status))
      else
        sending_direction = @server ? 1 : 2
        if direction == sending_direction
          stream.stop_send
        else
          stream.cancel_receive
        end
      end
    end

    def close
      return if @closed
      @closed = true
      @shutdown.close
      ws.close
      @controls.close
      @data.close
      streams.each_value { |stream| stream.fail(StreamError.new("Tunnel disconnected", 503)) }
      streams.clear
    end
  end
end
