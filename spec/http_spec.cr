require "./spec_helper"

describe Tune::HTTPWire do
  it "rejects ambiguous and malformed framing" do
    ["Content-Length: 1\r\nTransfer-Encoding: chunked", "Content-Length: 1\r\nContent-Length: 2", "Content-Length: -1", "Transfer-Encoding: gzip, chunked", " folded: header"].each do |headers|
      expect_raises(Tune::HTTPWire::Error) do
        Tune::HTTPWire.head(IO::Memory.new("POST / HTTP/1.1\r\nHost: test\r\n#{headers}\r\n\r\n"))
      end
    end
  end

  it "streams chunks, discards trailers and rejects early EOF" do
    headers = HTTP::Headers{"Transfer-Encoding" => "chunked"}
    body = Tune::HTTPWire::Body.new(IO::Memory.new("3\r\nabc\r\n2;extension=x\r\nde\r\n0\r\nX-Trailer: ignored\r\n\r\n"), headers)
    body.gets_to_end.should eq("abcde")
    expect_raises(IO::EOFError) do
      Tune::HTTPWire::Body.new(IO::Memory.new("ab"), HTTP::Headers{"Content-Length" => "3"}).gets_to_end
    end
  end

  it "enforces limits on unknown-length uploads" do
    body = Tune::HTTPWire::Body.new(IO::Memory.new("4\r\ndata\r\n0\r\n\r\n"), HTTP::Headers{"Transfer-Encoding" => "chunked"}, 3_i64)
    expect_raises(Tune::HTTPWire::Error) { body.gets_to_end }
  end

  it "strips connection-nominated and untrusted forwarding headers" do
    clean = Tune::HTTPWire.clean(HTTP::Headers{"Connection" => "keep-alive, X-Secret", "X-Secret" => "hidden", "X-Forwarded-For" => "forged", "Content-Type" => "text/plain"}, true)
    clean.has_key?("X-Secret").should be_false
    clean.has_key?("X-Forwarded-For").should be_false
    clean["Content-Type"].should eq("text/plain")
  end
end
