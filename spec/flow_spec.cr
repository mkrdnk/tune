require "./spec_helper"

class InspectableSession < Tune::Protocol::Session
  def deliver(frame : Tune::Protocol::Frame)
    dispatch(frame)
  end
end

describe "Multiplexing and flow control" do
  it "bounds individual buffers and rejects DATA beyond the receive window" do
    session = InspectableSession.new(Tune::Protocol::WebSocket.new(IO::Memory.new, false), false)
    session.on_open { |stream, payload| }
    session.deliver(Tune::Protocol::Frame.new(:open, 1_u32))
    4.times { session.deliver(Tune::Protocol::Frame.new(:data, 1_u32, Bytes.new(16_384))) }
    session.streams[1_u32].buffered.should eq(65_536)
    expect_raises(Tune::Protocol::Error) { session.deliver(Tune::Protocol::Frame.new(:data, 1_u32, Bytes[1])) }
  end

  it "enforces the shared session receive window across streams" do
    session = InspectableSession.new(Tune::Protocol::WebSocket.new(IO::Memory.new, false), false)
    session.on_open { |stream, payload| }
    17.times { |i| session.deliver(Tune::Protocol::Frame.new(:open, (i + 1).to_u32)) }
    16.times do |i|
      4.times { session.deliver(Tune::Protocol::Frame.new(:data, (i + 1).to_u32, Bytes.new(16_384))) }
    end
    expect_raises(Tune::Protocol::Error) { session.deliver(Tune::Protocol::Frame.new(:data, 17_u32, Bytes[1])) }
  end

  it "rejects sequencing errors, oversized credits and reused IDs" do
    session = InspectableSession.new(Tune::Protocol::WebSocket.new(IO::Memory.new, false), false)
    session.on_open { |stream, payload| }
    session.deliver(Tune::Protocol::Frame.new(:open, 1_u32))
    expect_raises(Tune::Protocol::Error) { session.deliver(Tune::Protocol::Frame.new(:open, 1_u32)) }
    expect_raises(Tune::Protocol::Error) do
      session.deliver(Tune::Protocol::Frame.new(:window_update, 1_u32, Tune::Protocol::Fields.new.u32(1).bytes))
    end
    session.deliver(Tune::Protocol::Frame.new(:end, 1_u32))
    expect_raises(Tune::Protocol::Error) { session.deliver(Tune::Protocol::Frame.new(:end, 1_u32)) }
    expect_raises(Tune::Protocol::Error) { session.deliver(Tune::Protocol::Frame.new(:data, 1_u32, Bytes[1])) }
  end

  it "allows a response after the request direction ends" do
    session = InspectableSession.new(Tune::Protocol::WebSocket.new(IO::Memory.new, false), false)
    session.on_open { |stream, payload| }
    session.deliver(Tune::Protocol::Frame.new(:open, 1_u32))
    session.deliver(Tune::Protocol::Frame.new(:end, 1_u32))
    stream = session.streams[1_u32]
    stream.read(Bytes.new(1)).should eq(0)
    stream.write("response".to_slice)
    stream.finish
    stream.send_closed?.should be_true
  end
end
