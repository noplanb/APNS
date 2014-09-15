module APNS
  class Server
    require 'socket'
    require 'openssl'
    require 'json'

    attr_accessor :host, :pem, :port, :pass
  
    def initialize(params={})
      @host = params[:host] || raise("Must initialize APNS with host gateway.")
      @port = params[:port] || 2195
      # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts
      @pem = params[:pem] || raise("Must initialize APNS with path to pem file.")
      @pass = nil
    end

    def send_notification(device_token, message)
      n = APNS::Notification.new(device_token, message)
      send_notifications([n])
    end

    def send_notifications(notifications)
      sock, ssl = open_connection
      packed_nofications = packed_nofications(notifications)
      ssl.write(packed_nofications)
      ssl.close
      sock.close
    end

    def packed_nofications(notifications)
      bytes = ''

      notifications.each do |notification|
        # Each notification frame consists of
        # 1. (e.g. protocol version) 2 (unsigned char [1 byte]) 
        # 2. size of the full frame (unsigend int [4 byte], big endian)
        pn = notification.packaged_notification
        bytes << ([2, pn.bytesize].pack('CN') + pn)
      end

      bytes
    end

    def feedback
      sock, ssl = feedback_connection

      apns_feedback = []

      while message = ssl.read(38)
        timestamp, token_size, token = message.unpack('N1n1H*')
        apns_feedback << [Time.at(timestamp), token]
      end

      ssl.close
      sock.close

      return apns_feedback
    end

    protected

    def open_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless @pem
      raise "The path to your pem file does not exist!" unless File.exist?(@pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(@pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(@pem), @pass)

      sock         = TCPSocket.new(@host, @port)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      return sock, ssl
    end

    def feedback_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless @pem
      raise "The path to your pem file does not exist!" unless File.exist?(@pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(@pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(@pem), @pass)

      fhost = @host.gsub('gateway','feedback')
      puts fhost

      sock         = TCPSocket.new(fhost, 2196)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      return sock, ssl
    end
  end
end
