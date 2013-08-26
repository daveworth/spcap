module Spcap
  class Packet
    attr_reader :raw_data, :caplen, :len, :time, :datalink
    
    def initialize(time,data,len,datalink)
      @time = time
      @raw_data = data
      @caplen = data.length
      @len = len
      @datalink = datalink
    end
    
    def size ; @len; end
    def length ; @len; end
    def ip? ; self.kind_of?(IPPacket) ; end
    def tcp? ; self.kind_of?(TCPPacket) ; end
    def udp? ; self.kind_of?(UDPPacket) ; end
    def time_i ; self.time.to_i ; end
  end
end
