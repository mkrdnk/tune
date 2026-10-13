require "yaml"

module Tune
  class Config
    include YAML::Serializable
    include YAML::Serializable::Strict

    class ServerOptions
      include YAML::Serializable
      include YAML::Serializable::Strict
      property bind : String = "127.0.0.1"
      property port : Int32 = 8000
      property domain : String = ""
      property public_url : String = ""
      property trusted_proxies : Array(String) = [] of String
      property insecure_local : Bool = false
    end

    class AuthOptions
      include YAML::Serializable
      include YAML::Serializable::Strict
      property mode : String = "private"
      property authorized_keys : String = "/etc/tune/authorized_keys"
      property allow_anonymous : Bool = true
    end

    class TunnelOptions
      include YAML::Serializable
      include YAML::Serializable::Strict
      property max_sessions : Int32 = 100
      property max_streams_per_session : Int32 = 32
      property blocked_names : Array(String) = [] of String
    end

    class Limits
      include YAML::Serializable
      include YAML::Serializable::Strict
      property max_connections : Int32 = 512
      property max_header_size : Int32 = 16_384
      property max_request_body : Int64 = 104_857_600_i64
      property connections_per_minute : Int32 = 30
      property requests_per_second : Int32 = 60
      property bytes_per_second : Int64 = 10_485_760_i64
    end

    class ACMEOptions
      include YAML::Serializable
      include YAML::Serializable::Strict
      property directory_url : String = "https://acme-v02.api.letsencrypt.org/directory"
      property email : String? = nil
      property terms_agreed : Bool = false
      property data_dir : String = ""
      property http_port : Int32 = 80
      property max_pending_orders : Int32 = 16
      property max_new_certificates_per_day : Int32 = 10
    end

    class TLSOptions
      include YAML::Serializable
      include YAML::Serializable::Strict
      property mode : String = "external"
      property acme : ACMEOptions = ACMEOptions.from_yaml("{}")
    end

    class LoggingOptions
      include YAML::Serializable
      include YAML::Serializable::Strict
      property level : String = "info"
    end

    property server : ServerOptions = ServerOptions.from_yaml("{}")
    property auth : AuthOptions = AuthOptions.from_yaml("{}")
    property tunnels : TunnelOptions = TunnelOptions.from_yaml("{}")
    property limits : Limits = Limits.from_yaml("{}")
    property tls : TLSOptions = TLSOptions.from_yaml("{}")
    property logging : LoggingOptions = LoggingOptions.from_yaml("{}")

    def validate
      server.domain = server.domain.downcase
      raise ArgumentError.new("server.domain must be a valid domain of at most 180 bytes") unless /\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/.matches?(server.domain) && server.domain.bytesize <= 180 && server.domain.split('.').all? { |label| valid_name?(label) }
      raise ArgumentError.new("Invalid port") unless (0..65_535).includes?(server.port)
      raise ArgumentError.new("auth.mode must be private or public") unless auth.mode.in?("private", "public")
      raise ArgumentError.new("tls.mode must be external or acme") unless tls.mode.in?("external", "acme")
      raise ArgumentError.new("Invalid log level") unless logging.level.downcase.in?("debug", "info", "warn", "error")
      raise ArgumentError.new("Invalid limits") unless tunnels.max_sessions > 0 && (1..1024).includes?(tunnels.max_streams_per_session) && limits.max_connections > 0 && (1024..16_384).includes?(limits.max_header_size) && limits.max_request_body > 0 && limits.connections_per_minute > 0 && limits.requests_per_second > 0 && limits.bytes_per_second > 0
      tunnels.blocked_names.each { |name| raise ArgumentError.new("Invalid blocked name") unless valid_name?(name) }
      server.trusted_proxies.each { |ip| Socket::IPAddress.new(ip, 0) }
      if server.insecure_local
        raise ArgumentError.new("insecure_local requires a loopback bind") unless Socket::IPAddress.new(server.bind, 0).loopback?
        raise ArgumentError.new("insecure_local cannot use ACME") if tls.mode == "acme"
      end
      server.public_url = "#{server.insecure_local ? "http" : "https"}://#{server.domain}" if server.public_url.empty?
      uri = URI.parse(server.public_url)
      raise ArgumentError.new("public_url must use the base domain without a path") unless uri.host == server.domain && uri.path.in?("", "/") && !uri.query && !uri.fragment && !uri.user && !uri.password
      raise ArgumentError.new("public_url requires HTTPS") unless uri.scheme == "https" || (server.insecure_local && uri.scheme == "http")
      if tls.mode == "acme"
        acme = tls.acme
        raise ArgumentError.new("ACME requires data_dir and terms_agreed: true") if acme.data_dir.empty? || !acme.terms_agreed
        raise ArgumentError.new("Invalid ACME limits or port") unless (0..65_535).includes?(acme.http_port) && acme.max_pending_orders > 0 && acme.max_new_certificates_per_day > 0
        raise ArgumentError.new("ACME directory must use HTTPS") unless URI.parse(acme.directory_url).scheme == "https"
      end
      self
    end

    def self.valid_name?(name : String) : Bool
      /\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/.matches?(name)
    end

    private def valid_name?(name : String) : Bool
      Config.valid_name?(name)
    end
  end

  class Bucket
    @tokens : Float64
    @updated = Time.instant

    def initialize(@rate : Float64, @capacity : Float64)
      @tokens = @capacity
    end

    def take(amount = 1.0) : Bool
      now = Time.instant
      @tokens = Math.min(@capacity, @tokens + (now - @updated).total_seconds * @rate)
      @updated = now
      return false if @tokens < amount
      @tokens -= amount
      true
    end

    def pace(count : Int32, &cancelled : -> Bool)
      deadline = Time.instant + 60.seconds
      until take(count.to_f)
        raise Protocol::StreamError.new("Stream cancelled") if cancelled.call
        raise Protocol::StreamError.new("Traffic pacing timeout", 504) if Time.instant > deadline
        sleep Math.min(count.to_f / @rate, 0.1).seconds
      end
    end
  end
end
