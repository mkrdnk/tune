require "./native"
require "base64"
require "digest/sha256"

module Tune::Security
  def self.check(result : Int32)
    raise OpenSSL::Error.new("Cryptographic operation failed") unless result > 0
  end

  def self.pointer(value : T) : T forall T
    raise OpenSSL::Error.new("Cryptographic allocation failed") if value.null?
    value
  end

  class Key
    getter handle : Void*

    def initialize(@handle : Void*)
      Security.pointer(@handle)
    end

    def self.generate(algorithm = "ED25519") : self
      ctx = Security.pointer(TuneCrypto.EVP_PKEY_CTX_new_from_name(nil, algorithm, nil))
      begin
        Security.check(TuneCrypto.EVP_PKEY_keygen_init(ctx))
        Security.check(TuneCrypto.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048)) if algorithm == "RSA"
        key = Pointer(Void).null
        Security.check(TuneCrypto.EVP_PKEY_keygen(ctx, pointerof(key)))
        new(key)
      ensure
        TuneCrypto.EVP_PKEY_CTX_free(ctx)
      end
    end

    def self.private_ed(bytes : Bytes) : self
      raise ArgumentError.new("Invalid Ed25519 seed") unless bytes.size == 32
      new(TuneCrypto.EVP_PKEY_new_raw_private_key_ex(nil, "ED25519", nil, bytes, bytes.size))
    end

    def self.public_ed(bytes : Bytes) : self
      raise ArgumentError.new("Invalid Ed25519 public key") unless bytes.size == 32
      new(TuneCrypto.EVP_PKEY_new_raw_public_key_ex(nil, "ED25519", nil, bytes, bytes.size))
    end

    def raw(private_key = false) : Bytes
      bytes = Bytes.new(32)
      size = 32_u64
      result = private_key ? TuneCrypto.EVP_PKEY_get_raw_private_key(handle, bytes, pointerof(size)) : TuneCrypto.EVP_PKEY_get_raw_public_key(handle, bytes, pointerof(size))
      Security.check(result)
      raise OpenSSL::Error.new("Invalid raw key length") unless size == 32
      bytes
    end

    def sign(message : Bytes, rsa = false) : Bytes
      ctx = Security.pointer(TuneCrypto.EVP_MD_CTX_new)
      begin
        digest = rsa ? TuneCrypto.EVP_sha256 : Pointer(Void).null.as(LibCrypto::EVP_MD)
        Security.check(TuneCrypto.EVP_DigestSignInit(ctx, nil, digest, nil, handle))
        size = 0_u64
        Security.check(TuneCrypto.EVP_DigestSign(ctx, nil, pointerof(size), message, message.size))
        bytes = Bytes.new(size.to_i)
        Security.check(TuneCrypto.EVP_DigestSign(ctx, bytes, pointerof(size), message, message.size))
        bytes[0, size.to_i]
      ensure
        TuneCrypto.EVP_MD_CTX_free(ctx)
      end
    end

    def verify(message : Bytes, signature : Bytes) : Bool
      return false unless signature.size == 64
      ctx = Security.pointer(TuneCrypto.EVP_MD_CTX_new)
      begin
        Security.check(TuneCrypto.EVP_DigestVerifyInit(ctx, nil, nil, nil, handle))
        TuneCrypto.EVP_DigestVerify(ctx, signature, signature.size, message, message.size) == 1
      ensure
        TuneCrypto.EVP_MD_CTX_free(ctx)
      end
    end

    def pem : String
      bio = Security.pointer(TuneCrypto.BIO_new(TuneCrypto.BIO_s_mem))
      begin
        Security.check(TuneCrypto.PEM_write_bio_PrivateKey(bio, handle, nil, nil, 0, nil, nil))
        bytes = Bytes.new(TuneCrypto.BIO_ctrl_pending(bio).to_i)
        Security.check(TuneCrypto.BIO_read(bio, bytes, bytes.size))
        String.new(bytes)
      ensure
        TuneCrypto.BIO_free(bio)
      end
    end

    def self.from_pem(pem : String) : self
      bio = Security.pointer(TuneCrypto.BIO_new_mem_buf(pem.to_slice, pem.bytesize))
      begin
        new(TuneCrypto.PEM_read_bio_PrivateKey(bio, nil, nil, nil))
      ensure
        TuneCrypto.BIO_free(bio)
      end
    end

    def parameter(name : String) : Bytes
      number = Pointer(Void).null
      Security.check(TuneCrypto.EVP_PKEY_get_bn_param(handle, name, pointerof(number)))
      begin
        bytes = Bytes.new((TuneCrypto.BN_num_bits(number) + 7) // 8)
        Security.check(TuneCrypto.BN_bn2bin(number, bytes))
        bytes
      ensure
        TuneCrypto.BN_free(number)
      end
    end

    def close
      return if @handle.null?
      TuneCrypto.EVP_PKEY_free(@handle)
      @handle = Pointer(Void).null
    end

    def finalize
      close
    end
  end
end
