module Spcap
  class Stream
    # File format :
    # File header
    #  4 Magic number
    #  2,2  Major version	Minor version
    #  4  Time zone offset always set to 0
    #  4  Time stamp accuracy always set to 0
    #  4  Snapshot length
    #  4  Link-layer header type

    MagicNumber = ["A1B2C3D4"].pack("H*")

    def initialize(istream)
      @istream = istream
      @magic_number = read(4)
      if @magic_number == MagicNumber
        @unpack_16 = "n"
        @unpack_32 = "N"
      else
        @unpack_16 = "v"
        @unpack_32 = "V"
      end
      @major_version, @minor_version = read16, read16
      read(8) # flush unused  time_zone_offset_always_0, timestamp_accuracy_always_0,
      @snapshot_length = read32
      @linklayer_header_type = read32
      # if header type is not ethernet raise an error !!
      raise InitializeException, "Not PCAP ethernet stream is not supported"if @linklayer_header_type != 1
      
    end
    def close
      @istream.close
    end
    def read(size)
      buf = @istream.read(size)
      return buf
    end
    
    def read16 
      buf = read(2)
      buf.unpack(@unpack_16).first
    end        
    
    def read32 
      buf = read(4)
      buf.unpack(@unpack_32).first
    end    
    #    Packets header
    #  4 Time stamp, seconds value
    #  4 Time stamp, microseconds value
    #  4 Length of captured packet data
    #  4 Un-truncated length of the packet data
    def each
      until(@istream.eof?)
        p = self.next
        yield p unless p.nil?
      end
    end
    
    def eof? ; @istream.eof? ; end
    
    def next
      time = Time.at(read32,read32)
      caplen = read32
      len = read32
      # TODO : move Ethernet parsing in Packet class constructor
      src_mac_address = read(6)
      dst_mac_address = read(6)
      protocol_type = read(2).unpack("n").first
      raw_data = read(caplen-14)
      if protocol_type == 0x0800
        p = Factory.get_packet(time,raw_data,len,@linklayer_header_type)
        if p.nil?
          Logger.warn "Spcap::Factory return nil packet"
        else
          return p
        end
      else
        # ignore non IPv4 packets
        Logger.info "Non-IPv4 packets are ignored Protocol = #{protocol_type}"
      end
      return nil      
    end
    
  end
end
