require_relative '../../test_helper'
 
describe Spcap::Stream do
  subject { Spcap::Stream.new(File.open('test/pcap_files/sample.pcap'))  }
  
  it "must be a Spcap::Stream" do
    subject.must_be_instance_of(Spcap::Stream)
  end
  
  it "must handle each without error" do
    subject.each{|p| }
    subject.must_respond_to(:each)
  end

end

describe Spcap::Scopy do
  subject { Spcap::Scopy.new(File.open('test/pcap_files/sample.pcap'))  }
  
  it "must be a Spcap::Scopy" do
    subject.must_be_instance_of(Spcap::Scopy)
  end
  
  it "must handle each without error" do
    subject.each{|p| }
    subject.must_respond_to(:each)
  end 
end


describe Spcap::TCPPacket do
  
  subject { packet = nil
            src = Spcap::Scopy.new(File.open('test/pcap_files/sample.pcap'))  
            src.each{|pkt|
              packet = pkt
              break
            }
            packet
          }
  before do
    @src = Spcap::IPAddress.new([174,100,92,122].pack("CCCC"))
    @sport = 45671
    @dst = Spcap::IPAddress.new([174,100,92,106].pack("CCCC"))
    @dport = 111  
    @channel = [[@src,@sport],[@dst,@dport]]
    @full_session = @channel.sort
  end
  it "must be a Spcap::TCPPacket" do
    subject.must_be_instance_of(Spcap::TCPPacket)
  end
  
  it "must handle full_session without error" do
    subject.full_session.must_equal(@full_session)
  end 
end