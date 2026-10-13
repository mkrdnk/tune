require "./crypto"
require "random/secure"

module Tune::Security
  module SSH
    def self.write(io : IO, bytes : Bytes)
      io.write_bytes(bytes.size.to_u32, IO::ByteFormat::NetworkEndian)
      io.write(bytes)
    end

    def self.read(io : IO, max = 16_384) : Bytes
      size = io.read_bytes(UInt32, IO::ByteFormat::NetworkEndian)
      raise ArgumentError.new("SSH key field too large") if size > max
      bytes = Bytes.new(size.to_i)
      io.read_fully(bytes)
      bytes
    end

    def self.blob(public_key : Bytes) : Bytes
      io = IO::Memory.new
      write(io, "ssh-ed25519".to_slice)
      write(io, public_key)
      io.to_slice
    end

    def self.public_key(blob : Bytes) : Bytes
      io = IO::Memory.new(blob)
      raise ArgumentError.new("Only ssh-ed25519 is supported") unless String.new(read(io)) == "ssh-ed25519"
      public_key = read(io)
      raise ArgumentError.new("Invalid public key") unless public_key.size == 32 && io.pos == io.size
      public_key
    end

    def self.fingerprint(public_key : Bytes) : String
      "SHA256:" + Base64.strict_encode(Digest::SHA256.digest(blob(public_key))).rstrip('=')
    end
  end

  class Identity
    getter key : Key

    def initialize(@key : Key)
    end

    def fingerprint : String
      SSH.fingerprint(key.raw)
    end

    def self.load(path : String) : self
      info = File.info(path)
      raise ArgumentError.new("Private key permissions must be 0600 or stricter") unless info.permissions.value & 0o077 == 0
      raise ArgumentError.new("Private key file too large") if info.size > 16_384
      text = File.read(path)
      lines = text.lines
      raise ArgumentError.new("Expected an OpenSSH private key") unless lines.first? == "-----BEGIN OPENSSH PRIVATE KEY-----" && lines.last? == "-----END OPENSSH PRIVATE KEY-----"
      bytes = Base64.decode(lines[1...-1].join)
      io = IO::Memory.new(bytes)
      raise ArgumentError.new("Invalid OpenSSH key") unless io.read_string(15) == "openssh-key-v1\0"
      cipher, kdf, options = SSH.read(io), SSH.read(io), SSH.read(io)
      raise ArgumentError.new("Encrypted OpenSSH keys are not supported") unless String.new(cipher) == "none" && String.new(kdf) == "none" && options.empty?
      raise ArgumentError.new("Expected one OpenSSH key") unless io.read_bytes(UInt32, IO::ByteFormat::NetworkEndian) == 1
      public_key = SSH.public_key(SSH.read(io))
      private_bytes = SSH.read(io)
      raise ArgumentError.new("Trailing OpenSSH data") unless io.pos == io.size && private_bytes.size % 8 == 0
      private_io = IO::Memory.new(private_bytes)
      check = private_io.read_bytes(UInt32, IO::ByteFormat::NetworkEndian)
      raise ArgumentError.new("OpenSSH check mismatch") unless check == private_io.read_bytes(UInt32, IO::ByteFormat::NetworkEndian)
      raise ArgumentError.new("Unsupported key type") unless String.new(SSH.read(private_io)) == "ssh-ed25519"
      inner_public, secret = SSH.read(private_io), SSH.read(private_io)
      SSH.read(private_io)
      raise ArgumentError.new("Inconsistent OpenSSH key") unless inner_public == public_key && secret.size == 64 && secret[32, 32] == public_key
      padding = 1
      while value = private_io.read_byte
        raise ArgumentError.new("Invalid OpenSSH padding") unless value == padding && padding <= 8
        padding += 1
      end
      key = Key.private_ed(secret[0, 32])
      raise ArgumentError.new("Public/private key mismatch") unless key.raw == public_key
      new(key)
    end

    def self.generate(path : String) : self
      raise ArgumentError.new("Key already exists; choose a different --identity path") if File.exists?(path) || File.exists?(path + ".pub") || File.symlink?(path) || File.symlink?(path + ".pub")
      parent = File.dirname(path)
      Dir.mkdir_p(parent, 0o700)
      key = Key.generate
      identity = new(key)
      private_io = IO::Memory.new
      check = Random::Secure.rand(UInt32)
      2.times { private_io.write_bytes(check, IO::ByteFormat::NetworkEndian) }
      SSH.write(private_io, "ssh-ed25519".to_slice)
      SSH.write(private_io, key.raw)
      private_bytes = Bytes.new(64)
      private_bytes[0, 32].copy_from(key.raw(true))
      private_bytes[32, 32].copy_from(key.raw)
      SSH.write(private_io, private_bytes)
      SSH.write(private_io, "tune".to_slice)
      pad = 1_u8
      until private_io.size % 8 == 0
        private_io.write_byte(pad)
        pad += 1
      end
      io = IO::Memory.new
      io << "openssh-key-v1\0"
      SSH.write(io, "none".to_slice)
      SSH.write(io, "none".to_slice)
      SSH.write(io, Bytes.empty)
      io.write_bytes(1_u32, IO::ByteFormat::NetworkEndian)
      SSH.write(io, SSH.blob(key.raw))
      SSH.write(io, private_io.to_slice)
      encoded = Base64.strict_encode(io.to_slice)
      pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + encoded.scan(/.{1,70}/).map(&.[0]).join('\n') + "\n-----END OPENSSH PRIVATE KEY-----\n"
      create_exclusive(path, 0o600) do |file|
        file << pem
        file.fsync
      end
      create_exclusive(path + ".pub", 0o644) do |file|
        file << "ssh-ed25519 " << Base64.strict_encode(SSH.blob(key.raw)) << " tune\n"
        file.fsync
      end
      identity
    end

    private def self.create_exclusive(path : String, permissions : Int32, &block : File ->)
      file = File.tempfile(".tune-key-", dir: File.dirname(path))
      begin
        File.chmod(file.path, permissions)
        yield file
        file.close
        File.link(file.path, path)
      ensure
        file.close
        file.delete
      end
    end
  end

  class AuthorizedKeys
    getter keys : Hash(String, Bytes)

    def initialize(path : String)
      raise ArgumentError.new("authorized_keys is too large") if File.size(path) > 1_048_576
      @keys = {} of String => Bytes
      File.each_line(path) do |line|
        line = line.strip
        next if line.empty? || line.starts_with?('#')
        parts = line.split(/\s+/, 3)
        raise ArgumentError.new("Expected ssh-ed25519 key; options are not supported") unless parts.size >= 2 && parts[0] == "ssh-ed25519"
        key = SSH.public_key(Base64.decode(parts[1]))
        @keys[SSH.fingerprint(key)] = key
      end
      raise ArgumentError.new("authorized_keys is empty") if @keys.empty?
    end
  end

  class Challenge
    getter nonce : Bytes = Random::Secure.random_bytes(32)
    @created = Time.instant
    @used = false

    def initialize(@url : String, @fingerprint : String, @name : String, @ttl = 30.seconds)
    end

    def transcript : Bytes
      self.class.transcript(@url, @fingerprint, @name, nonce)
    end

    def self.transcript(url : String, fingerprint : String, name : String, nonce : Bytes) : Bytes
      fields = Protocol::Fields.new.string("Tune client authentication").string(Protocol::VERSION).string(url).string(fingerprint).string(name)
      fields.io.write(nonce)
      fields.bytes
    end

    def verify(public_key : Bytes?, signature : Bytes) : Bool
      valid = !@used && Time.instant - @created <= @ttl
      @used = true
      # Unknown keys take the same challenge/signature path.
      key = Key.public_ed(public_key || Bytes.new(32))
      result = key.verify(transcript, signature)
      valid && !public_key.nil? && result
    ensure
      key.try &.close
    end
  end
end
