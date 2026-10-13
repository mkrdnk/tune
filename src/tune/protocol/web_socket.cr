require "http/web_socket"
require "random/secure"

module Tune::Protocol
  # A bounded RFC 6455 transport. Compression extensions are never negotiated.
  class WebSocket
    getter io : IO
    getter? closed = false
    @write_lock = Mutex.new

    def initialize(@io : IO, @client : Bool)
    end

    def send(frame : Frame)
      packet(2_u8, frame.encode)
    end

    def receive : Frame
      message = IO::Memory.new
      fragmented = false
      loop do
        first = io.read_byte || raise IO::EOFError.new
        second = io.read_byte || raise IO::EOFError.new
        raise Error.new("Reserved WebSocket bits") unless first & 0x70 == 0
        final = first & 0x80 != 0
        opcode = first & 0x0f
        masked = second & 0x80 != 0
        raise Error.new("Invalid WebSocket masking") unless masked == !@client
        short_length = second & 0x7f
        length = case short_length
                 when 126
                   value = io.read_bytes(UInt16, IO::ByteFormat::NetworkEndian).to_u64
                   raise Error.new("Noncanonical WebSocket length") if value < 126
                   value
                 when 127
                   value = io.read_bytes(UInt64, IO::ByteFormat::NetworkEndian)
                   raise Error.new("Noncanonical WebSocket length") if value < 65_536 || value >> 63 != 0
                   value
                 else
                   short_length.to_u64
                 end
        control = opcode >= 8
        if control
          raise Error.new("Invalid control frame") if !final || length > 125
        elsif length > MAX_FRAME || message.size.to_u64 + length > MAX_FRAME
          raise Error.new("WebSocket message too large")
        end
        mask = Bytes.new(masked ? 4 : 0)
        io.read_fully(mask)
        body = Bytes.new(length.to_i)
        io.read_fully(body)
        body.each_index { |i| body[i] ^= mask[i % 4] } if masked
        case opcode
        when 8
          raise Error.new("Invalid close payload") if body.size == 1
          close
          raise IO::EOFError.new
        when 9
          packet(10_u8, body)
        when 10
        when 2, 0
          raise Error.new("Invalid fragmentation") if (opcode == 0) != fragmented
          message.write(body)
          return Frame.decode(message.to_slice) if final
          fragmented = true
        else
          raise Error.new("Expected binary WebSocket message")
        end
      end
    end

    private def packet(opcode : UInt8, body : Bytes)
      @write_lock.synchronize do
        raise IO::Error.new("WebSocket closed") if @closed
        io.write_byte(0x80_u8 | opcode)
        bit = @client ? 0x80_u8 : 0_u8
        if body.size < 126
          io.write_byte(bit | body.size.to_u8)
        elsif body.size <= UInt16::MAX
          io.write_byte(bit | 126_u8)
          io.write_bytes(body.size.to_u16, IO::ByteFormat::NetworkEndian)
        else
          io.write_byte(bit | 127_u8)
          io.write_bytes(body.size.to_u64, IO::ByteFormat::NetworkEndian)
        end
        if @client
          mask = Random::Secure.random_bytes(4)
          io.write(mask)
          copy = body.dup
          copy.each_index { |i| copy[i] ^= mask[i % 4] }
          io.write(copy)
        else
          io.write(body)
        end
        io.flush
      end
    end

    def close
      return if @closed
      @closed = true
      io.close
    rescue IO::Error
      # Closing an already disconnected peer is idempotent.
    end
  end
end
