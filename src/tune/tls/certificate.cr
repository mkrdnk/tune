module Tune::TLS
  class ExpiredCertificate < Exception
  end

  def self.atomic_write(path : String, content : String)
    file = File.tempfile(".tune-", dir: File.dirname(path))
    begin
      File.chmod(file.path, 0o600)
      file << content
      file.flush
      file.fsync
      file.close
      File.rename(file.path, path)
      File.open(File.dirname(path)) { |directory| directory.fsync }
    ensure
      file.close
      file.delete if File.exists?(file.path)
    end
  end

  def self.csr(key : Security::Key, hostname : String) : Bytes
    request = Security.pointer(TuneCrypto.X509_REQ_new)
    extensions = Security.pointer(TuneCrypto.OPENSSL_sk_new_null)
    extension = TuneCrypto.X509V3_EXT_conf_nid(nil, nil, 85, "DNS:#{hostname}")
    begin
      raise OpenSSL::Error.new("Cannot create SAN") if extension.null?
      Security.check(TuneCrypto.X509_REQ_set_version(request, 0))
      Security.check(TuneCrypto.X509_REQ_set_pubkey(request, key.handle))
      Security.check(TuneCrypto.OPENSSL_sk_push(extensions, extension.as(Void*)))
      Security.check(TuneCrypto.X509_REQ_add_extensions(request, extensions))
      Security.check(TuneCrypto.X509_REQ_sign(request, key.handle, TuneCrypto.EVP_sha256))
      size = TuneCrypto.i2d_X509_REQ(request, nil)
      Security.check(size)
      bytes = Bytes.new(size)
      pointer = bytes.to_unsafe
      Security.check(TuneCrypto.i2d_X509_REQ(request, pointerof(pointer)))
      bytes
    ensure
      TuneCrypto.X509_REQ_free(request)
      TuneCrypto.X509_EXTENSION_free(extension) unless extension.null?
      TuneCrypto.OPENSSL_sk_free(extensions)
    end
  end

  record Certificate, hostname : String, context : OpenSSL::SSL::Context::Server, not_before : Time, expires : Time do
    def self.load(path : String, hostname : String) : self
      raise ArgumentError.new("Certificate bundle too large") if File.size(path) > 1_048_576
      pem = File.read(path)
      key = Security::Key.from_pem(pem)
      bio = Security.pointer(TuneCrypto.BIO_new_mem_buf(pem.to_slice, pem.bytesize))
      cert = TuneCrypto.PEM_read_bio_X509(bio, nil, nil, nil)
      begin
        raise OpenSSL::Error.new("Invalid X509 certificate") if cert.null?
        Security.check(TuneCrypto.X509_check_host(cert, hostname, hostname.bytesize, 34_u32, nil))
        Security.check(TuneCrypto.X509_check_private_key(cert, key.handle))
        not_before = time(TuneCrypto.X509_get0_notBefore(cert))
        expires = time(TuneCrypto.X509_get0_notAfter(cert))
        raise ArgumentError.new("Certificate is not yet valid") if not_before > Time.utc
        raise ExpiredCertificate.new("Certificate has expired") if expires <= Time.utc
        verify_chain(cert, bio)
        context = OpenSSL::SSL::Context::Server.new
        context.certificate_chain = path
        context.private_key = path
        new(hostname, context, not_before, expires)
      ensure
        TuneCrypto.X509_free(cert) unless cert.null?
        TuneCrypto.BIO_free(bio)
        key.close
      end
    end

    private def self.time(value : Void*) : Time
      tm = uninitialized LibC::Tm
      Security.check(TuneCrypto.ASN1_TIME_to_tm(value, pointerof(tm)))
      Time.utc(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
    end

    private def self.verify_chain(leaf : LibCrypto::X509, bio : LibCrypto::Bio*)
      store = TuneCrypto.X509_STORE_new
      context = TuneCrypto.X509_STORE_CTX_new
      chain = Security.pointer(TuneCrypto.OPENSSL_sk_new_null)
      intermediates = [] of LibCrypto::X509
      begin
        raise OpenSSL::Error.new("Cannot allocate certificate verifier") if store.null? || context.null?
        Security.check(TuneCrypto.X509_STORE_set_default_paths(store))
        loop do
          certificate = TuneCrypto.PEM_read_bio_X509(bio, nil, nil, nil)
          break if certificate.null?
          intermediates << certificate
          Security.check(TuneCrypto.OPENSSL_sk_push(chain, certificate.as(Void*)))
        end
        # PEM EOF leaves an error in OpenSSL's thread-local error queue.
        while LibCrypto.err_get_error != 0
        end
        Security.check(TuneCrypto.X509_STORE_CTX_init(context, store, leaf, chain))
        Security.check(LibCrypto.x509_verify_cert(context))
      ensure
        TuneCrypto.X509_STORE_CTX_free(context) unless context.null?
        TuneCrypto.X509_STORE_free(store) unless store.null?
        intermediates.each { |certificate| TuneCrypto.X509_free(certificate) }
        TuneCrypto.OPENSSL_sk_free(chain)
      end
    end

    def renewal_due? : Bool
      Time.utc >= not_before + (expires - not_before) * 0.65
    end
  end
end
