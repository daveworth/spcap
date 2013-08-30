module Spcap
  class Scopy < Stream
    CURRENT_OUT_FILENAME = 'pcapcopy.tmp'
    FILENAME_EXTENTION = '.pcap'
    def initialize(istream,opt = {})
      @tmpname = CURRENT_OUT_FILENAME
      @wpath = opt[:wpath] || ''
      @prefix = opt[:prefix] || ''
      @limit = opt[:limit] || 10000
      @counter = 0
      @ostream = new_file
      super(istream)
      @header = @magic_number + [@major_version, @minor_version, 0, 0, @snapshot_length, 
        @linklayer_header_type].pack(@unpack_16 + @unpack_16 + @unpack_32 + @unpack_32 + 
        @unpack_32 + @unpack_32)
    end
    
    def read(size)
      buf = @istream.read(size)
      @ostream.write(buf)
      return buf
    end
    
    def new_file ; File.new(File.expand_path(@wpath,@tmpname),"w") ; end
    
    def backup_name
      @wpath + @prefix + Time.now.strftime("%Y%m%d%H%M%S%6N") + FILENAME_EXTENTION
    end
    
    def end_file
      p = @ostream.to_path
      @ostream.close
      File.rename(p,backup_name) 
    end
    
    def switch_out
      end_file
      @ostream = new_file
      @ostream.write(@header)
      super(@ostream)
    end
    
    def each
      super do |pkt|
        @counter += 1
        if @counter == @limit
          switch_out
          @counter = 0
        end
        yield pkt
      end
    end
  end
end