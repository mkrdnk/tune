module Tune::TLS
  class Manager
    @certificates = {} of String => Certificate
    @pending = Set(String).new
    @retry = {} of String => Int64
    @lock : File
    @acme : ACME
    @budget_day : String = ""
    @budget_used = 0
    @closed = false
    @order_slot = Channel(Nil).new(1)
    @issuer_retry = 0_i64

    def initialize(@options : Config::ACMEOptions)
      Dir.mkdir_p(options.data_dir, 0o700)
      raise ArgumentError.new("ACME data_dir must have mode 0700") unless File.info(options.data_dir).permissions.value & 0o077 == 0
      @lock = File.new(File.join(options.data_dir, "lock"), "a", perm: 0o600)
      @lock.flock_exclusive(blocking: false)
      @acme = ACME.new(options)
      @order_slot.send(nil)
      if File.exists?(state_path)
        state = JSON.parse(File.read(state_path))
        @budget_day = state["day"].as_s
        @budget_used = state["used"].as_i
        @issuer_retry = state["issuer_retry"]?.try(&.as_i64) || 0_i64
        state["retry"].as_h.each { |host, time| @retry[host] = time.as_i64 }
      end
      Dir.glob(File.join(options.data_dir, "cert-*.pem")).each do |path|
        hostname = File.basename(path)[5...-4]
        begin
          @certificates[hostname] = Certificate.load(path, hostname)
        rescue ExpiredCertificate
          File.delete(path)
        rescue ex
          Tune::Log.warn { "Ignoring invalid/expired cached certificate for #{hostname}: #{ex.class}" }
        end
      end
      raise ArgumentError.new("ACME certificate cache exceeds 1000 files") if Dir.glob(File.join(options.data_dir, "cert-*.pem")).size > 1000
    end

    def challenge(hostname : String, path : String) : String?
      @acme.challenge(hostname, path)
    end

    def available?(hostname : String) : Bool
      !!@certificates[hostname]?.try { |cert| cert.expires > Time.utc }
    end

    def context(hostname : String) : OpenSSL::SSL::Context::Server
      certificate = @certificates[hostname]? || raise ACMEError.new("Certificate unavailable")
      raise ACMEError.new("Certificate expired") if certificate.expires <= Time.utc
      certificate.context.on_server_name do |name|
        cert = @certificates[name.downcase]?
        raise ACMEError.new("Unknown TLS hostname") unless cert && cert.expires > Time.utc
        cert.context
      end
      certificate.context
    end

    def ensure_certificate(hostname : String)
      raise ACMEError.new("TLS manager stopped") if @closed
      raise ACMEError.new("Invalid certificate hostname") unless hostname.bytesize <= 253 && hostname.split('.').all? { |label| Config.valid_name?(label) }
      @certificates.reject! do |name, certificate|
        expired = certificate.expires <= Time.utc && !@pending.includes?(name)
        File.delete(cert_path(name)) if expired && File.exists?(cert_path(name))
        expired
      end
      existing = @certificates[hostname]?
      return if existing && !existing.renewal_due?
      @retry.reject! { |_, time| time <= Time.utc.to_unix }
      if @issuer_retry > Time.utc.to_unix
        return if existing && existing.expires > Time.utc
        raise ACMEError.new("Certificate issuer is cooling down", Time.unix(@issuer_retry))
      end
      if retry_at = @retry[hostname]?
        if retry_at > Time.utc.to_unix
          return if existing && existing.expires > Time.utc
          raise ACMEError.new("Certificate issuance is cooling down", Time.unix(retry_at))
        end
      end
      if @pending.includes?(hostname)
        deadline = Time.instant + 160.seconds
        while @pending.includes?(hostname)
          raise ACMEError.new("Certificate provisioning timed out") if Time.instant > deadline || @closed
          sleep 50.milliseconds
        end
        raise ACMEError.new("Certificate provisioning failed") unless available?(hostname)
        return
      end
      raise ACMEError.new("Certificate queue full") if @pending.size >= @options.max_pending_orders
      @pending << hostname
      acquired = false
      begin
        select
        when @order_slot.receive
          acquired = true
        when timeout(20.seconds)
          raise ACMEError.new("Certificate queue wait timed out")
        end
        raise ACMEError.new("TLS manager stopped") if @closed
        if @issuer_retry > Time.utc.to_unix
          raise ACMEError.new("Certificate issuer is cooling down", Time.unix(@issuer_retry))
        end
        unless existing
          raise ACMEError.new("Certificate cache is full") if Dir.glob(File.join(@options.data_dir, "cert-*.pem")).size >= 1000
          consume_budget
        end
        key = Security::Key.generate("RSA")
        certificate = @acme.issue(hostname, TLS.csr(key, hostname))
        bundle = certificate + "\n" + key.pem
        temporary = File.tempfile(".certificate-", dir: @options.data_dir)
        begin
          temporary << bundle
          temporary.flush
          checked = Certificate.load(temporary.path, hostname)
          TLS.atomic_write(cert_path(hostname), bundle)
          @certificates[hostname] = checked
          @retry.delete(hostname)
          persist
        ensure
          temporary.close
          temporary.delete
        end
        Tune::Log.info { "Certificate installed: #{hostname}" }
      rescue ex
        retry_at = ex.is_a?(ACMEError) ? ex.retry_at : nil
        if retry_at
          @issuer_retry = Math.max(@issuer_retry, retry_at.to_unix)
        elsif @retry.size < 1000
          @retry[hostname] = (Time.utc + 15.minutes).to_unix
        end
        persist
        raise ex unless existing && existing.expires > Time.utc
        Tune::Log.warn { "Certificate renewal deferred for #{hostname}; existing certificate remains valid" }
      ensure
        key.try &.close
        @pending.delete(hostname)
        @order_slot.send(nil) if acquired
      end
    end

    private def consume_budget
      day = Time.utc.to_s("%F")
      if @budget_day != day
        @budget_day = day
        @budget_used = 0
      end
      raise ACMEError.new("Daily certificate budget exhausted", Time.utc.at_beginning_of_day + 1.day) if @budget_used >= @options.max_new_certificates_per_day
      @budget_used += 1
      persist
    end

    private def state_path : String
      File.join(@options.data_dir, "state.json")
    end

    private def cert_path(hostname : String) : String
      File.join(@options.data_dir, "cert-#{hostname}.pem")
    end

    private def persist
      TLS.atomic_write(state_path, {"day" => @budget_day, "used" => @budget_used, "retry" => @retry, "issuer_retry" => @issuer_retry}.to_json)
    end

    def close
      return if @closed
      @closed = true
      # In-flight requests own their key until completion; don't free it underneath a fiber.
      if @pending.empty?
        @acme.close
        @lock.close
      else
        spawn do
          until @pending.empty?
            sleep 100.milliseconds
          end
          @acme.close
          @lock.close
        end
      end
    end
  end
end
