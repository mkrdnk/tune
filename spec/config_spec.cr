require "./spec_helper"

describe Tune::Config do
  it "rejects unknown options instead of accepting ineffective settings" do
    expect_raises(YAML::ParseException) { Tune::Config.from_yaml("limits:\n  imaginary: 5\n") }
  end

  it "defaults to private mode and external TLS" do
    config = Tune::Config.from_yaml("{}")
    config.auth.mode.should eq("private")
    config.tls.mode.should eq("external")
    expect_raises(ArgumentError) { config.validate }
  end

  it "requires deliberate ACME activation and confines insecure HTTP to loopback" do
    config = Tune::Config.from_yaml("server:\n  domain: example.com\n")
    config.tls.mode = "acme"
    expect_raises(ArgumentError) { config.validate }
    config.tls.mode = "external"
    config.server.insecure_local = true
    config.server.bind = "0.0.0.0"
    expect_raises(ArgumentError) { config.validate }
  end
end
