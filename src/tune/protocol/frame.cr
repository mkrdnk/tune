module Tune::Protocol
  VERSION        = "tune/1"
  MAX_FRAME      = 65_536
  MAX_PAYLOAD    = MAX_FRAME - 9
  CHUNK          =    16_384
  STREAM_WINDOW  =    65_536
  SESSION_WINDOW = 1_048_576

  class Error < Exception
  end

  enum Type : UInt8
    Hello        = 1
    Challenge
    Auth
    Welcome
    Open
    Headers
    Data
    End
    Reset
    WindowUpdate
    Ping
    Pong
    Error
  end

  record Frame, type : Type, stream_id : UInt32 = 0_u32, payload : Bytes = Bytes.empty do
    def encode : Bytes
      raise Error.new("Frame too large") if payload.size > MAX_PAYLOAD
      io = IO::Memory.new
      io.write_byte(type.value)
      io.write_bytes(stream_id, IO::ByteFormat::NetworkEndian)
      io.write_bytes(payload.size.to_u32, IO::ByteFormat::NetworkEndian)
      io.write(payload)
      io.to_slice
    end

    def self.read(io : IO) : self
      type = Type.from_value?(io.read_byte || raise IO::EOFError.new)
      raise Error.new("Unknown frame type") unless type
      id = io.read_bytes(UInt32, IO::ByteFormat::NetworkEndian)
      size = io.read_bytes(UInt32, IO::ByteFormat::NetworkEndian)
      raise Error.new("Frame too large") if size > MAX_PAYLOAD
      payload = Bytes.new(size.to_i)
      io.read_fully(payload)
      new(type, id, payload)
    end

    def self.decode(bytes : Bytes) : self
      io = IO::Memory.new(bytes)
      frame = read(io)
      raise Error.new("Trailing frame data") unless io.pos == bytes.size
      frame
    end
  end

  class Fields
    getter io : IO::Memory

    def initialize
      @io = IO::Memory.new
    end

    def initialize(bytes : Bytes)
      @io = IO::Memory.new(bytes)
    end

    def u32(value : Int) : self
      io.write_bytes(value.to_u32, IO::ByteFormat::NetworkEndian)
      self
    end

    def u32 : UInt32
      io.read_bytes(UInt32, IO::ByteFormat::NetworkEndian)
    end

    def string(value : String) : self
      u32(value.bytesize)
      io.write(value.to_slice)
      self
    end

    def string(max = 16_384) : String
      size = u32
      raise Error.new("Field too large") if size > max || size > io.size - io.pos
      value = io.read_string(size.to_i)
      raise Error.new("Invalid UTF-8") unless value.valid_encoding?
      value
    end

    def finish : Nil
      raise Error.new("Trailing message fields") unless io.pos == io.size
    end

    def bytes : Bytes
      io.to_slice
    end
  end
end
