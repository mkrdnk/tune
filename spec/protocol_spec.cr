require "spec"
require "../src/tune/protocol/frame"
require "../src/tune/protocol/web_socket"

class PartialReadIO < IO
  def initialize(@io : IO)
  end

  def read(slice : Bytes) : Int32
    @io.read(slice[0, Math.min(slice.size, 3)])
  end

  def write(slice : Bytes) : Nil
    raise IO::Error.new("Read-only test IO")
  end
end

describe Tune::Protocol do
  it "round trips every frame type and binary payload" do
    Tune::Protocol::Type.each do |type|
      frame = Tune::Protocol::Frame.new(type, 17_u32, Bytes[0, 255, 42])
      Tune::Protocol::Frame.decode(frame.encode).should eq(frame)
    end
  end

  it "rejects oversized, unknown, truncated and concatenated frames" do
    expect_raises(Tune::Protocol::Error) { Tune::Protocol::Frame.decode(Bytes[255, 0, 0, 0, 0, 0, 0, 0, 0]) }
    expect_raises(Tune::Protocol::Error) { Tune::Protocol::Frame.decode(Bytes[7, 0, 0, 0, 1, 0, 1, 0, 0]) }
    expect_raises(IO::EOFError) { Tune::Protocol::Frame.decode(Bytes[7]) }
    expect_raises(Tune::Protocol::Error) { Tune::Protocol::Frame.decode(Bytes[7, 0, 0, 0, 1, 0, 0, 0, 0, 1]) }
  end

  it "round trips length prefixed fields and checks trailing data" do
    fields = Tune::Protocol::Fields.new.string("tune/1").u32(42)
    read = Tune::Protocol::Fields.new(fields.bytes)
    read.string.should eq("tune/1")
    expect_raises(Tune::Protocol::Error) { read.finish }
    read.u32.should eq(42)
    read.finish
  end

  it "masks client frames and reads them on the server" do
    io = IO::Memory.new
    Tune::Protocol::WebSocket.new(io, true).send(Tune::Protocol::Frame.new(:data, 1_u32, Bytes[0, 255]))
    io.rewind
    Tune::Protocol::WebSocket.new(io, false).receive.payload.should eq(Bytes[0, 255])
  end

  it "rejects advertised oversized websocket payloads before reading a body" do
    io = IO::Memory.new(Bytes[0x82, 127, 0, 0, 0, 0, 0, 2, 0, 0])
    expect_raises(Tune::Protocol::Error) { Tune::Protocol::WebSocket.new(io, true).receive }
  end

  it "decodes a frame from partial reads" do
    frame = Tune::Protocol::Frame.new(:data, 3_u32, Random::Secure.random_bytes(257))
    io = PartialReadIO.new(IO::Memory.new(frame.encode))
    Tune::Protocol::Frame.read(io).should eq(frame)
  end

  it "decodes websocket continuations and rejects unmasked client messages" do
    frame = Tune::Protocol::Frame.new(:data, 1_u32, Bytes[1, 2, 3]).encode
    io = IO::Memory.new
    io.write(Bytes[2, 5])
    io.write(frame[0, 5])
    io.write(Bytes[0x80, (frame.size - 5).to_u8])
    io.write(frame[5..])
    io.rewind
    Tune::Protocol::WebSocket.new(io, true).receive.payload.should eq(Bytes[1, 2, 3])
    expect_raises(Tune::Protocol::Error) do
      Tune::Protocol::WebSocket.new(IO::Memory.new(Bytes[0x82, 0]), false).receive
    end
  end
end
