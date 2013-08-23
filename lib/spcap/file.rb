module Spcap
  class File
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
      magic_number = istream.read(4)
      if magic_number == MagicNumber
        @unpack_16 = "n"
        @unpack_32 = "N"
      else
        @unpack_16 = "v"
        @unpack_32 = "V"
      end
      @major_version, @minor_version = read16, read16
      @istream.read(8) # flush unused  time_zone_offset_always_0, timestamp_accuracy_always_0,
      @snapshot_length = read32
      @linklayer_header_type = read32
    end

    def read16 ; @istream.read(2).unpack(@unpack_16).first ; end        
    
    def read32 ; @istream.read(4).unpack(@unpack_32).first ; end    
    #    Packets header
    #  4 Time stamp, seconds value
    #  4 Time stamp, microseconds value
    #  4 Length of captured packet data
    #  4 Un-truncated length of the packet data
    def each
      until(@istream.eof?)
        time = Time.at(read32,read32)
        caplen = read32
        len = read32
        raw_data = @istream.read(caplen)
        yield Packet.new(time,raw_data,len,@linklayer_header_type)
      end
    end
  end
end
