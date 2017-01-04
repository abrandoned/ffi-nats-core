require "ffi/nats/core/version"
require 'rubygems'
require 'ffi'
require 'thread'
require 'securerandom'

#trap(:TRAP) do
#  ::Thread.list.each do |thread|
#    $stdout << <<-THREAD_TRACE
#    #{thread.inspect}:
#    #{thread.backtrace && thread.backtrace.join($INPUT_RECORD_SEPARATOR)}"
#    THREAD_TRACE
#  end
#end

module FFI
  module Nats
    module Core
      extend FFI::Library
      ffi_lib_flags :now, :global

      ##
      # ffi-rzmq-core for reference
      #
      # https://github.com/chuckremes/ffi-rzmq-core/blob/master/lib/ffi-rzmq-core/libzmq.rb
      #
      begin
        # bias the library discovery to a path inside the gem first, then
        # to the usual system paths
        inside_gem = File.join(File.dirname(__FILE__), '..', '..', 'ext')
        local_path = FFI::Platform::IS_WINDOWS ? ENV['PATH'].split(';') : ENV['PATH'].split(':')
        env_path = [ ENV['NATS_LIB_PATH'] ].compact
        rbconfig_path = RbConfig::CONFIG["libdir"]
        homebrew_path = nil

        # RUBYOPT set by RVM breaks 'brew' so we need to unset it.
        rubyopt = ENV.delete('RUBYOPT')

        begin
          stdout, stderr, status = Open3.capture3("brew", "--prefix")
          homebrew_path  = if status.success?
                             "#{stdout.chomp}/lib"
                           else
                             '/usr/local/homebrew/lib'
                           end
        rescue
          # Homebrew doesn't exist
        end

        # Restore RUBYOPT after executing 'brew' above.
        ENV['RUBYOPT'] = rubyopt

        # Search for libnats in the following order...
        NATS_LIB_PATHS = ([inside_gem] + env_path + local_path + [rbconfig_path] + [
          '/usr/local/lib', '/opt/local/lib', homebrew_path, '/usr/lib64'
        ]).compact.map{|path| "#{path}/libnats.#{FFI::Platform::LIBSUFFIX}"}
        ffi_lib(NATS_LIB_PATHS + %w{libnats})

      rescue LoadError
        if NATS_LIB_PATHS.any? {|path|
          File.file? File.join(path, "libnats.#{FFI::Platform::LIBSUFFIX}")}
          warn "Unable to load this gem. The libnats library exists, but cannot be loaded."
          warn "Set NATS_LIB_PATH if custom load path is desired"
          warn "If this is Windows:"
          warn "-  Check that you have MSVC runtime installed or statically linked"
          warn "-  Check that your DLL is compiled for #{FFI::Platform::ADDRESS_SIZE} bit"
        else
          warn "Unable to load this gem. The libnats library (or DLL) could not be found."
          warn "Set NATS_LIB_PATH if custom load path is desired"
          warn "If this is a Windows platform, make sure libnats.dll is on the PATH."
          warn "If the DLL was built with mingw, make sure the other two dependent DLLs,"
          warn "libgcc_s_sjlj-1.dll and libstdc++6.dll, are also on the PATH."
          warn "For non-Windows platforms, make sure libnats is located in this search path:"
          warn NATS_LIB_PATHS.inspect
        end
        raise LoadError, "The libnats library (or DLL) could not be loaded"
      end

      enum :NATS_CONN_STATUS, [
        :DISCONNECTED, 0,  #///< The connection has been disconnected
        :CONNECTING,       #///< The connection is in the process or connecting
        :CONNECTED,        #///< The connection is connected
        :CLOSED,           #///< The connection is closed
        :RECONNECTING      #///< The connection is in the process or reconnecting
      ]

      NATS_STATUS = enum [
        :NATS_OK, 0,                     #< Success
        :NATS_ERR,                       #< Generic error
        :NATS_PROTOCOL_ERROR,            #< Error when parsing a protocol message, or not getting the expected message.
        :NATS_IO_ERROR,                  #< IO Error (network communication).
        :NATS_LINE_TOO_LONG,             #< The protocol message read from the socket does not fit in the read buffer.
        :NATS_CONNECTION_CLOSED,         #< Operation on this connection failed because the connection is closed.
        :NATS_NO_SERVER,                 #< Unable to connect, the server could not be reached or is not running.
        :NATS_STALE_CONNECTION,          #< The server closed our connection because it did not receive PINGs at the expected interval.
        :NATS_SECURE_CONNECTION_WANTED,  #< The client is configured to use TLS, but the server is not.
        :NATS_SECURE_CONNECTION_REQUIRED,#< The server expects a TLS connection.
        :NATS_CONNECTION_DISCONNECTED,   #< The connection was disconnected. Depending on the configuration, the connection may reconnect.
        :NATS_CONNECTION_AUTH_FAILED,    #< The connection failed due to authentication error.
        :NATS_NOT_PERMITTED,             #< The action is not permitted.
        :NATS_NOT_FOUND,                 #< An action could not complete because something was not found. So far, this is an internal error.
        :NATS_ADDRESS_MISSING,           #< Incorrect URL. For instance no host specified in the URL.
        :NATS_INVALID_SUBJECT,           #< Invalid subject, for instance NULL or empty string.
        :NATS_INVALID_ARG,               #< An invalid argument is passed to a function. For instance passing NULL to an API that does not accept this value.
        :NATS_INVALID_SUBSCRIPTION,      #< The call to a subscription function fails because the subscription has previously been closed.
        :NATS_INVALID_TIMEOUT,           #< Timeout must be positive numbers.
        :NATS_ILLEGAL_STATE,             #< An unexpected state, for instance calling #natsSubscription_NextMsg() on an asynchronous subscriber.
        :NATS_SLOW_CONSUMER,             #< The maximum number of messages waiting to be delivered has been reached. Messages are dropped.
        :NATS_MAX_PAYLOAD,               #< Attempt to send a payload larger than the maximum allowed by the NATS Server.
        :NATS_MAX_DELIVERED_MSGS,        #< Attempt to receive more messages than allowed, for instance because of #natsSubscription_AutoUnsubscribe().
        :NATS_INSUFFICIENT_BUFFER,       #< A buffer is not large enough to accommodate the data.
        :NATS_NO_MEMORY,                 #< An operation could not complete because of insufficient memory.
        :NATS_SYS_ERROR,                 #< Some system function returned an error.
        :NATS_TIMEOUT,                   #< An operation timed-out. For instance #natsSubscription_NextMsg().
        :NATS_FAILED_TO_INITIALIZE,      #< The library failed to initialize.
        :NATS_NOT_INITIALIZED,           #< The library is not yet initialized.
        :NATS_SSL_ERROR                  #< An SSL error occurred when trying to establish a connection.
      ]

      # message handler callback definition
      callback :on_message_function, [:pointer, :pointer, :pointer, :pointer], :void

      # nats
      attach_function :nats_Close, [], :void, :blocking => true
      attach_function :nats_GetLastError, [:pointer], :strptr, :blocking => true
      attach_function :nats_GetLastErrorStack, [:buffer_out, :size_t], :int, :blocking => true
      attach_function :nats_GetVersion, [], :strptr, :blocking => true
      attach_function :nats_GetVersionNumber, [], :uint32, :blocking => true
      attach_function :nats_Now, [], :int64, :blocking => true
      attach_function :nats_NowInNanoSeconds, [], :int64, :blocking => true
      attach_function :nats_Open, [:int64], :int, :blocking => true
      # attach_function :nats_PrintLastErrorStack, [:pointer], :void
      attach_function :nats_SetMessageDeliveryPoolSize, [:int], :int, :blocking => true
      attach_function :nats_Sleep, [:int64], :void, :blocking => true

      # natsConnection
      attach_function :natsConnection_Buffered, [:pointer], :int, :blocking => true
      attach_function :natsConnection_Close, [:pointer], :void, :blocking => true
      attach_function :natsConnection_Connect, [:pointer, :pointer], :int, :blocking => true
      attach_function :natsConnection_ConnectTo, [:pointer, :string], :int, :blocking => true
      attach_function :natsConnection_Destroy, [:pointer], :void, :blocking => true
      attach_function :natsConnection_Flush, [:pointer], :int, :blocking => true
      attach_function :natsConnection_GetConnectedServerId, [:pointer, :buffer_out, :size_t], :int, :blocking => true
      attach_function :natsConnection_GetConnectedUrl, [:pointer, :buffer_out, :size_t], :int, :blocking => true
      attach_function :natsConnection_GetLastError, [:pointer, :pointer], :int, :blocking => true
      attach_function :natsConnection_GetMaxPayload, [:pointer], :int64, :blocking => true
      attach_function :natsConnection_GetStats, [:pointer, :pointer], :int, :blocking => true
      attach_function :natsConnection_IsClosed, [:pointer], :bool, :blocking => true
      attach_function :natsConnection_IsReconnecting, [:pointer], :bool, :blocking => true
      attach_function :natsConnection_Publish, [:pointer, :string, :pointer, :int], NATS_STATUS, :blocking => true
      attach_function :natsConnection_PublishMsg, [:pointer, :pointer], :int, :blocking => true
      attach_function :natsConnection_PublishRequest, [:pointer, :string, :string, :string, :pointer, :int], :int, :blocking => true
      attach_function :natsConnection_PublishRequestString, [:pointer, :string, :string, :string], :int, :blocking => true
      attach_function :natsConnection_PublishString, [:pointer, :string, :string], NATS_STATUS, :blocking => true
      attach_function :natsConnection_Request, [:pointer, :pointer, :string, :string, :int, :int64], :int, :blocking => true
      attach_function :natsConnection_RequestString, [:pointer, :pointer, :string, :string, :int64], :int, :blocking => true
      attach_function :natsConnection_Status, [:pointer], :int, :blocking => true
      attach_function :natsConnection_Subscribe, [:pointer, :pointer, :string, :on_message_function, :pointer], :int, :blocking => true
      attach_function :natsConnection_SubscribeSync, [:pointer, :pointer, :string], :int, :blocking => true
      attach_function :natsConnection_SubscribeTimeout, [:pointer, :pointer, :string, :int64, :on_message_function, :pointer], :int, :blocking => true
      attach_function :natsConnection_QueueSubscribe, [:pointer, :pointer, :string, :string, :on_message_function, :pointer], :int, :blocking => true
      attach_function :natsConnection_QueueSubscribeSync, [:pointer, :pointer, :string, :string], :int, :blocking => true
      attach_function :natsConnection_QueueSubscribeTimeout, [:pointer, :pointer, :string, :string, :int64, :on_message_function, :pointer], :int, :blocking => true

      # natsInbox
      attach_function :natsInbox_Create, [:pointer], :int, :blocking => true
      attach_function :natsInbox_Destroy, [:pointer], :void, :blocking => true

      # natsMsg
      attach_function :natsMsg_Create, [:pointer, :string, :string, :string, :int], :int, :blocking => true
      attach_function :natsMsg_Destroy, [:pointer], :void, :blocking => true
      attach_function :natsMsg_GetSubject, [:pointer], :strptr, :blocking => true
      attach_function :natsMsg_GetReply, [:pointer], :strptr, :blocking => true
      attach_function :natsMsg_GetData, [:pointer], :strptr, :blocking => true
      attach_function :natsMsg_GetDataLength, [:pointer], :int, :blocking => true

      # natsNUID
      attach_function :natsNUID_free, [], :void, :blocking => true
      attach_function :natsNUID_init, [], :void, :blocking => true
      attach_function :natsNUID_Next, [:string, :int], :void, :blocking => true

      # natsOptions
      attach_function :natsOptions_Create, [:pointer], :int, :blocking => true
      attach_function :natsOptions_Destroy, [:pointer], :void, :blocking => true
      attach_function :natsOptions_IPResolutionOrder, [:pointer, :int], :int, :blocking => true
      attach_function :natsOptions_LoadCATrustedCertificates, [:pointer, :string], :int, :blocking => true
      attach_function :natsOptions_LoadCertificatesChain, [:pointer, :string, :string], :int, :blocking => true
      attach_function :natsOptions_SetAllowReconnect, [:pointer, :bool], :int, :blocking => true
      attach_function :natsOptions_SetCiphers, [:pointer, :string], :int, :blocking => true
      attach_function :natsOptions_SetExpectedHostname, [:pointer, :string], :int, :blocking => true
      attach_function :natsOptions_SetMaxPingsOut, [:pointer, :int64], :int, :blocking => true
      attach_function :natsOptions_SetMaxPendingMsgs, [:pointer, :int], :int, :blocking => true
      attach_function :natsOptions_SetMaxReconnect, [:pointer, :int], :int, :blocking => true
      attach_function :natsOptions_SetReconnectBufSize, [:pointer, :int], :int, :blocking => true
      attach_function :natsOptions_SetReconnectWait, [:pointer, :int64], :int, :blocking => true
      attach_function :natsOptions_SetName, [:pointer, :string], :int, :blocking => true
      attach_function :natsOptions_SetNoRandomize, [:pointer, :bool], :int, :blocking => true
      attach_function :natsOptions_SetPedantic, [:pointer, :bool], :int, :blocking => true
      attach_function :natsOptions_SetPingInterval, [:pointer, :int64], :int, :blocking => true
      attach_function :natsOptions_SetSecure, [:pointer, :bool], :int, :blocking => true
      attach_function :natsOptions_SetServers, [:pointer, :pointer, :int], :int, :blocking => true
      attach_function :natsOptions_SetTimeout, [:pointer, :int64], :int, :blocking => true
      attach_function :natsOptions_SetToken, [:pointer, :string], :int, :blocking => true
      attach_function :natsOptions_SetURL, [:pointer, :string], :int, :blocking => true
      attach_function :natsOptions_SetUserInfo, [:pointer, :string, :string], :int, :blocking => true
      attach_function :natsOptions_SetVerbose, [:pointer, :bool], :int, :blocking => true
      attach_function :natsOptions_UseGlobalMessageDelivery, [:pointer, :bool], :void, :blocking => true

      # natsSubscription
      attach_function :natsSubscription_AutoUnsubscribe, [:pointer, :int], :int, :blocking => true
      attach_function :natsSubscription_ClearMaxPending, [:pointer], :int, :blocking => true
      attach_function :natsSubscription_Destroy, [:pointer], :void, :blocking => true
      attach_function :natsSubscription_GetDelivered, [:pointer, :pointer], :int, :blocking => true
      attach_function :natsSubscription_GetDropped, [:pointer, :pointer], :int, :blocking => true
      attach_function :natsSubscription_GetMaxPending, [:pointer, :pointer, :pointer], :int, :blocking => true
      attach_function :natsSubscription_GetPending, [:pointer, :pointer, :pointer], :int, :blocking => true
      attach_function :natsSubscription_GetPendingLimits, [:pointer, :pointer, :pointer], :int, :blocking => true
      attach_function :natsSubscription_GetStats, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int, :blocking => true
      attach_function :natsSubscription_IsValid, [:pointer], :bool, :blocking => true
      attach_function :natsSubscription_NextMsg, [:pointer, :pointer, :int64], :int, :blocking => true
      attach_function :natsSubscription_NoDeliveryDelay, [:pointer], :int, :blocking => true
      attach_function :natsSubscription_SetPendingLimits, [:pointer, :int, :int], :int, :blocking => true
      attach_function :natsSubscription_Unsubscribe, [:pointer], :int, :blocking => true

      # natsStatistics
      attach_function :natsStatistics_Create, [:pointer], :int, :blocking => true
      attach_function :natsStatistics_Destroy, [:pointer], :void, :blocking => true
      attach_function :natsStatistics_GetCounts, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int, :blocking => true

      # natsStatus
      attach_function :natsStatus_GetText, [NATS_STATUS], :strptr, :blocking => true


      SubscribeCallback = FFI::Function.new(:void, [:pointer, :pointer, :pointer, :pointer], :blocking => true) do |conn, sub, msg, closure|
        #queue_name = closure.read_string
        #queue_name = FFI::Nats::Core.natsMsg_GetSubject(msg)
        #queue_for_and_remove(queue_name) << FFI::Nats::Core.natsMsg_GetData(msg)

        #print "+"
        reply_to, _ = FFI::Nats::Core.natsMsg_GetReply(msg)
        FFI::Nats::Core.natsConnection_PublishString(conn, reply_to, "thanks")
        FFI::Nats::Core.natsConnection_Flush(conn)
        FFI::Nats::Core.natsMsg_Destroy(msg)
      end

      def self.subscribe(connection, subscription, subject, &blk)
        if blk.arity == 4
          FFI::Nats::Core.natsConnection_Subscribe(subscription, connection, subject, blk, nil)
        else
          raise "subscribe block arity must be 4 ... ish"
        end
      end

      def self.run_subscribe(connection)
        subscription = FFI::MemoryPointer.new :pointer
        uuid = SecureRandom.uuid
        q = Queue.new
        #q = queue_for(uuid)

        #FFI::Nats::Core.natsConnection_Subscribe(subscription, connection, uuid, FFI::Nats::Core::SubscribeCallback, nil)
        subscribe(connection, subscription, uuid) do |conn, sub, msg, closure|
          print "+"
          data, _ = FFI::Nats::Core.natsMsg_GetData(msg)
          subject, _ = FFI::Nats::Core.natsMsg_GetSubject(msg)
          q << data
          FFI::Nats::Core.natsMsg_Destroy(msg)
          FFI::Nats::Core.natsSubscription_Unsubscribe(sub)
        end

        #FFI::Nats::Core.natsSubscription_AutoUnsubscribe(subscription.get_pointer(0), 1)
        sub = subscription.get_pointer(0)
        #FFI::Nats::Core.natsSubscription_AutoUnsubscribe(sub, 1)
        FFI::Nats::Core.natsConnection_PublishString(connection, uuid, "hello from the other side")
        #FFI::Nats::Core.natsConnection_Flush(connection)

        q.pop
        FFI::Nats::Core.natsSubscription_Destroy(sub)
      end

      def self.test_subscribe
        threads = []

        1.times do
          threads << Thread.new do
            connection_pointer = FFI::MemoryPointer.new :pointer
            FFI::Nats::Core.natsConnection_ConnectTo(connection_pointer, "nats://localhost:4222")
            connection = connection_pointer.get_pointer(0)

            1_000.times do
              run_subscribe(connection)
            end

            FFI::Nats::Core.natsConnection_Flush(connection)
            FFI::Nats::Core.natsConnection_Close(connection)
            FFI::Nats::Core.natsConnection_Destroy(connection)
          end
        end

        threads.map(&:join)
      end

      def self.test_request_reply
        start = Time.now
        num_threads = 8
        publish_per_thread = 100_000
        threads = []
        subject = "hello"
        message = "world"
        reply = "thanks"
        message_size = message.size

        subscription = FFI::MemoryPointer.new :pointer
        opts_pointer = FFI::MemoryPointer.new :pointer
        conn_t = FFI::MemoryPointer.new :pointer

        FFI::Nats::Core.natsOptions_Create(opts_pointer)
        opts_pointer = opts_pointer.get_pointer(0)
        FFI::Nats::Core.natsOptions_SetURL(opts_pointer, "nats://localhost:4222")
        FFI::Nats::Core.natsOptions_UseGlobalMessageDelivery(opts_pointer, true)

        FFI::Nats::Core.natsConnection_Connect(conn_t, opts_pointer)
        conn_t = conn_t.get_pointer(0)
        FFI::Nats::Core.natsConnection_Subscribe(subscription, conn_t, subject, FFI::Nats::Core::SubscribeCallback, nil)
        FFI::Nats::Core.natsConnection_Flush(conn_t)

        num_threads.times do
          threads << Thread.new do
            options_pointer = FFI::MemoryPointer.new :pointer
            connection_pointer = FFI::MemoryPointer.new :pointer

            FFI::Nats::Core.natsOptions_Create(options_pointer)
            options_pointer = options_pointer.get_pointer(0)
            FFI::Nats::Core.natsOptions_SetURL(options_pointer, "nats://localhost:4222")

            FFI::Nats::Core.natsConnection_Connect(connection_pointer, options_pointer)
            connection_pointer = connection_pointer.get_pointer(0)

            publish_per_thread.times do
              FFI::MemoryPointer.new(:pointer) do |message_pointer|
                FFI::Nats::Core.natsConnection_RequestString(message_pointer, connection_pointer, subject, message, 1000)
                FFI::Nats::Core.natsMsg_Destroy(message_pointer.get_pointer(0))
              end
            end
          end
        end

        threads.map(&:join)

        FFI::Nats::Core.natsSubscription_Unsubscribe(subscription.get_pointer(0))
        FFI::Nats::Core.natsSubscription_Destroy(subscription.get_pointer(0))

        finish = Time.now
        time_diff = finish.to_i - start.to_i
        throughput = (num_threads * publish_per_thread)
        puts <<-FINISH
    THREADS: #{num_threads}
    PUBLISH PER THREAD: #{publish_per_thread}
    START: #{start}
    FINISH: #{finish}
    PER SECOND: #{time_diff == 0 ? throughput : throughput/time_diff}
    FINISH
      end

      def self.test_threaded_single_connection
        start = Time.now
        num_threads = 8
        publish_per_thread = 500_000
        publishes = 0
        threads = []
        subject = "hello"
        message = "world"
        message_size = message.size

        options_pointer = FFI::MemoryPointer.new :pointer
        connection_pointer = FFI::MemoryPointer.new :pointer

        FFI::Nats::Core.natsOptions_Create(options_pointer)
        options_pointer = options_pointer.get_pointer(0)
        FFI::Nats::Core.natsOptions_SetURL(options_pointer, "nats://0.0.0.0:4222")

        FFI::Nats::Core.natsConnection_Connect(connection_pointer, options_pointer)
        connection_pointer = connection_pointer.get_pointer(0)

        num_threads.times do
          threads << Thread.new do
            publish_per_thread.times do
              status = FFI::Nats::Core.natsConnection_Publish(connection_pointer, subject, message, message.size)
              puts status unless NATS_STATUS[status] == NATS_STATUS[:NATS_OK]
            end
          end
        end

        threads.map(&:join)
        FFI::Nats::Core.natsConnection_Flush(connection_pointer)
        finish = Time.now
        total_time = finish.to_i - start.to_i
        total_time = 1 if total_time.zero?
        puts <<-FINISH
    PUBLISHES: #{publishes}
    THREADS: #{num_threads}
    PUBLISH PER THREAD: #{publish_per_thread}
    START: #{start}
    FINISH: #{finish}
    PER SECOND: #{(num_threads * publish_per_thread)/total_time}
    FINISH
      end

      def self.test_threaded
        start = Time.now
        num_threads = 4
        publish_per_thread = 100_000
        threads = []
        subject = "hello"
        message = "world"
        message_size = message.size

        num_threads.times do
          threads << Thread.new do
            connection_pointer = nil

            if false
              connection_pointer = FFI::MemoryPointer.new :pointer
              FFI::Nats::Core.natsConnection_ConnectTo(connection_pointer, "nats://localhost:4222")
              connection_pointer = connection_pointer.get_pointer(0)
            else
              options_pointer = FFI::MemoryPointer.new :pointer
              connection_pointer = FFI::MemoryPointer.new :pointer

              FFI::Nats::Core.natsOptions_Create(options_pointer)
              options_pointer = options_pointer.get_pointer(0)
              FFI::Nats::Core.natsOptions_SetURL(options_pointer, "nats://0.0.0.0:4222")

              FFI::Nats::Core.natsConnection_Connect(connection_pointer, options_pointer)
              connection_pointer = connection_pointer.get_pointer(0)
            end

            publish_per_thread.times do
              FFI::Nats::Core.natsConnection_PublishString(connection_pointer, subject, message)
            end
          end
        end

        threads.map(&:join)
        finish = Time.now
        total_time = finish.to_i - start.to_i
        total_time = 1 if total_time.zero?
        puts <<-FINISH
    THREADS: #{num_threads}
    PUBLISH PER THREAD: #{publish_per_thread}
    START: #{start}
    FINISH: #{finish}
    PER SECOND: #{(num_threads * publish_per_thread)/total_time}
    FINISH
      end

    end
  end
end
