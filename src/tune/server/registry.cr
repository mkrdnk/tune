module Tune::Server
  class Entry
    getter name : String
    getter fingerprint : String
    getter ws : Protocol::WebSocket
    property session : Protocol::Session?
    getter requests : Bucket
    getter upload : Bucket
    getter download : Bucket

    def initialize(@name : String, @fingerprint : String, @ws : Protocol::WebSocket, limits : Config::Limits)
      @requests = Bucket.new(limits.requests_per_second.to_f, limits.requests_per_second * 2.0)
      capacity = Math.max(Protocol::CHUNK, Math.min(limits.bytes_per_second, 1_048_576)).to_f
      @upload = Bucket.new(limits.bytes_per_second.to_f, capacity)
      @download = Bucket.new(limits.bytes_per_second.to_f, capacity)
    end

    def close
      session.try &.close
      ws.close
    end
  end

  class Registry
    @entries = {} of String => Entry
    @mutex = Mutex.new

    def reserve(requested : String, fingerprint : String, ws : Protocol::WebSocket, config : Config) : Entry
      @mutex.synchronize do
        raise Protocol::StreamError.new("Session limit exceeded", 429) if @entries.size >= config.tunnels.max_sessions
        if !requested.empty?
          raise ArgumentError.new("Anonymous sessions cannot request names") if config.auth.mode == "public"
          raise ArgumentError.new("Invalid tunnel name") unless Config.valid_name?(requested)
        end
        name = requested.empty? ? Random::Secure.hex(16) : requested
        raise ArgumentError.new("Tunnel name is blocked") if config.tunnels.blocked_names.includes?(name)
        raise ArgumentError.new("Tunnel name is already in use") if @entries.has_key?(name)
        entry = Entry.new(name, fingerprint, ws, config.limits)
        @entries[name] = entry
        entry
      end
    end

    def find(name : String) : Entry?
      @mutex.synchronize { @entries[name]? }
    end

    def remove(entry : Entry)
      @mutex.synchronize { @entries.delete(entry.name) if @entries[entry.name]? == entry }
    end

    def entries : Array(Entry)
      @mutex.synchronize { @entries.values }
    end

    def size : Int32
      @mutex.synchronize { @entries.size }
    end
  end
end
