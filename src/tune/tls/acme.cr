require "json"

module Tune::TLS
  class ACMEError < Exception
    getter retry_at : Time?

    def initialize(message : String, @retry_at : Time? = nil)
      super(message)
    end
  end

  class ACME
    @directory : JSON::Any?
    @nonce : String?
    @account_url : String?
    @key : Security::Key
    @mutex = Mutex.new
    @challenges = {} of {String, String} => String

    def initialize(@options : Config::ACMEOptions)
      key_path = File.join(@options.data_dir, "account-key.pem")
      @key = if File.exists?(key_path)
               Security::Key.from_pem(File.read(key_path))
             else
               key = Security::Key.generate("RSA")
               TLS.atomic_write(key_path, key.pem)
               key
             end
      account_path = File.join(@options.data_dir, "account.json")
      if File.exists?(account_path)
        account = JSON.parse(File.read(account_path))
        raise ArgumentError.new("ACME directory changed; use a separate data_dir") unless account["directory"].as_s == @options.directory_url
        @account_url = account["url"].as_s
      end
    end

    def challenge(hostname : String, path : String) : String?
      prefix = "/.well-known/acme-challenge/"
      return unless path.starts_with?(prefix)
      @challenges[{hostname, path[prefix.size..]}]?
    end

    def issue(hostname : String, csr : Bytes) : String
      # Serializing ACME transactions also prevents nonce reuse between orders.
      @mutex.synchronize do
        directory = @directory ||= JSON.parse(request("GET", @options.directory_url)[2])
        unless @account_url
          payload = JSON.build do |json|
            json.object do
              json.field "termsOfServiceAgreed", @options.terms_agreed
              if email = @options.email
                json.field "contact", ["mailto:#{email}"]
              end
            end
          end
          _, headers, _ = signed(directory["newAccount"].as_s, payload, use_jwk: true)
          @account_url = headers["Location"]? || raise ACMEError.new("CA omitted account URL")
          TLS.atomic_write(File.join(@options.data_dir, "account.json"), {"directory" => @options.directory_url, "url" => @account_url}.to_json)
        end
        deadline = Time.instant + 150.seconds
        _, headers, content = signed(directory["newOrder"].as_s, {"identifiers" => [{"type" => "dns", "value" => hostname}]}.to_json)
        order_url = headers["Location"]? || raise ACMEError.new("CA omitted order URL")
        order = JSON.parse(content)
        order["authorizations"].as_a.each do |authorization_url|
          authorization = JSON.parse(signed(authorization_url.as_s, "")[2])
          identifier = authorization["identifier"]
          raise ACMEError.new("Unexpected ACME identifier") unless identifier["type"].as_s == "dns" && identifier["value"].as_s == hostname && authorization["wildcard"]?.try(&.as_bool) != true
          next if authorization["status"].as_s == "valid"
          challenge = authorization["challenges"].as_a.find { |item| item["type"].as_s == "http-01" } || raise ACMEError.new("CA does not offer HTTP-01")
          token = challenge["token"].as_s
          raise ACMEError.new("Invalid challenge token") unless /\A[A-Za-z0-9_-]{16,256}\z/.matches?(token)
          @challenges[{hostname, token}] = token + "." + self.class.base64(Digest::SHA256.digest(jwk))
          begin
            signed(challenge["url"].as_s, "{}")
            poll(authorization_url.as_s, ["valid"], deadline)
          ensure
            @challenges.delete({hostname, token})
          end
        end
        ready = poll(order_url, ["ready", "valid"], deadline)
        if ready["status"].as_s != "valid"
          signed(order["finalize"].as_s, {"csr" => self.class.base64(csr)}.to_json)
        end
        completed = poll(order_url, ["valid"], deadline)
        signed(completed["certificate"].as_s, "")[2]
      end
    end

    private def poll(url : String, states : Array(String), deadline : Time::Instant) : JSON::Any
      loop do
        raise ACMEError.new("ACME operation timed out") if Time.instant > deadline
        _, headers, body = signed(url, "")
        result = JSON.parse(body)
        state = result["status"].as_s
        return result if states.includes?(state)
        if state.in?("invalid", "expired", "revoked", "deactivated")
          problem = result["error"]?
          result["challenges"]?.try(&.as_a).try &.each do |challenge|
            problem ||= challenge["error"]?
          end
          kind = problem.try { |error| error["type"]?.try(&.as_s) }
          raise ACMEError.new("ACME validation failed (#{state}, #{kind || "unknown problem"})")
        end
        wait = retry_time(headers).try { |time| Math.max((time - Time.utc).total_seconds, 1.0) } || 1.0
        raise ACMEError.new("CA requested delayed retry", Time.utc + wait.seconds) if wait.seconds > deadline - Time.instant
        sleep wait.seconds
      end
    end

    private def jwk : String
      {"e" => self.class.base64(@key.parameter("e")), "kty" => "RSA", "n" => self.class.base64(@key.parameter("n"))}.to_json
    end

    def self.base64(bytes : Bytes) : String
      Base64.urlsafe_encode(bytes, padding: false)
    end

    private def signed(url : String, payload : String, use_jwk = false) : {Int32, HTTP::Headers, String}
      3.times do
        unless @nonce
          directory = @directory.not_nil!
          request("HEAD", directory["newNonce"].as_s)
        end
        nonce = @nonce || raise ACMEError.new("CA omitted Replay-Nonce")
        @nonce = nil
        protected_header = JSON.build do |json|
          json.object do
            json.field "alg", "RS256"
            json.field "nonce", nonce
            json.field "url", url
            if use_jwk
              json.field "jwk" { json.raw(jwk) }
            else
              json.field "kid", @account_url.not_nil!
            end
          end
        end
        encoded_header = self.class.base64(protected_header.to_slice)
        encoded_payload = self.class.base64(payload.to_slice)
        signature = @key.sign("#{encoded_header}.#{encoded_payload}".to_slice, rsa: true)
        body = {"protected" => encoded_header, "payload" => encoded_payload, "signature" => self.class.base64(signature)}.to_json
        result = request("POST", url, body)
        status, headers, content = result
        if status >= 400
          error = JSON.parse(content)
          next if error["type"]?.try(&.as_s) == "urn:ietf:params:acme:error:badNonce"
          raise ACMEError.new("ACME #{status}: #{error["type"]?.try(&.as_s) || "request failed"}", retry_time(headers))
        end
        return result
      end
      raise ACMEError.new("ACME nonce retries exhausted")
    end

    private def request(method : String, url : String, body : String? = nil) : {Int32, HTTP::Headers, String}
      uri = URI.parse(url)
      raise ACMEError.new("ACME resource must use HTTPS") unless uri.scheme == "https" && uri.host && !uri.user && !uri.password && !uri.fragment
      client = HTTP::Client.new(uri)
      client.connect_timeout = 10.seconds
      client.read_timeout = 30.seconds
      client.write_timeout = 30.seconds
      headers = HTTP::Headers{"User-Agent" => "Tune/#{Tune::VERSION}", "Content-Type" => "application/jose+json", "Accept" => "application/json, application/pem-certificate-chain"}
      client.exec(method, uri.request_target, headers, body) do |response|
        output = IO::Memory.new
        buffer = Bytes.new(8192)
        if input = response.body_io?
          while (count = input.read(buffer)) > 0
            raise ACMEError.new("CA response exceeds 1 MiB") if output.size + count > 1_048_576
            output.write(buffer[0, count])
          end
        end
        @nonce = response.headers["Replay-Nonce"]? if response.headers.has_key?("Replay-Nonce")
        {response.status_code, response.headers, output.to_s}
      end
    ensure
      client.try &.close
    end

    private def retry_time(headers : HTTP::Headers) : Time?
      value = headers["Retry-After"]?
      return unless value
      if seconds = value.to_i?
        Time.utc + Math.max(seconds, 0).seconds
      else
        HTTP.parse_time(value)
      end
    end

    def close
      @key.close
    end
  end
end
