require "spec"
require "../src/tune/library"

Log.setup(:debug, Log::IOBackend.new(STDERR)) if ENV["TUNE_SPEC_DEBUG"]?
