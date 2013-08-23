module Spcap
# 1 	Internet Control Message Protocol 	ICMP
# 2 	Internet Group Management Protocol 	IGMP
# 6 	Transmission Control Protocol 	TCP
# 17 	User Datagram Protocol 	UDP
# 41 	IPv6 encapsulation 	ENCAP
# 89 	Open Shortest Path First 	OSPF
# 132 	Stream Control Transmission Protocol 	SCTP
  class Factory
    def self.get_packet(time,raw_data,len,linklayer_header_type)
      if ( ( ( raw_data.getbyte(0) & 0xF0) / 16 ) == 4 )
        if raw_data.getbyte(9) == 6 
          return TCPPacket.new(time,raw_data,len,linklayer_header_type)
        end
      end
      Logger.warn "Spcap::Factory only support TCP over IPv4 packet other packet are dropped"
    end
  end
end