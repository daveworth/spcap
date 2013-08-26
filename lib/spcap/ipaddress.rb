module Spcap
  class IPAddress
    attr_reader :address
    
    def initialize(address)
      @address = address
    end
    
    # Return true if two addresses are the same address.
    def ==(other)
      @address == other.adress
    end
    
    def hash
      @address.hash
    end
    
    # Return host name correspond to this address.
    def hostname
      # Not yet implemented
      to_num_s
    end

    # Return the value of IP address as integer.
    def to_i
      @address.unpackt("N").first
    end
    

    #Return numerical string representation
    def to_num_s
      @address.unpack("CCCC").join('.')
    end
    
    def to_s
      to_num_s
    end
  end
end