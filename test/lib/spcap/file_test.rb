require_relative '../../test_helper'
 
describe Spcap::Stream do
  subject { Spcap::Stream.new(File.open('test/pcap_files/sample.pcap'))  }
  
  it "must be a Spcap::Stream" do
    subject.must_be_instance_of(Spcap::Stream)
  end
  
  it "is enumerable" do
    subject.must_respond_to(:each)
  end

  it "must handle each without error" do
    subject.each{|p| }
  end

  it "has a concept of length" do  # this tests the Enumerable mixin
    subject.must_respond_to(:count)
  end
end

describe Spcap::Scopy do
  let(:temp_path) { File.join("test", "tmp")}
  subject { Spcap::Scopy.new(File.open('test/pcap_files/sample.pcap'), wpath: temp_path)  }
  before do
    @counter=0
  end
  after do
    Dir.glob("test/tmp/*.pcap").each do |temp_filename|
      File.unlink(temp_filename)
    end
  end
  it "must be a Spcap::Scopy" do
    subject.must_be_instance_of(Spcap::Scopy)
  end
  
  it "must handle each without error" do
    subject.each{|p| @counter += 1}
    @counter.must_equal(37)
    subject.must_respond_to(:each)
  end 
end


describe Spcap::TCPPacket do
  
  let(:temp_path) { File.join("test", "tmp")}
  subject { packet = nil
            src = Spcap::Scopy.new(File.open('test/pcap_files/sample.pcap'), wpath: temp_path)
            packet = src.next
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
  after do
    Dir.glob("test/tmp/*.pcap").each do |temp_filename|
      File.unlink(temp_filename)
    end
  end
  it "must be a Spcap::TCPPacket" do
    subject.must_be_instance_of(Spcap::TCPPacket)
  end
  
  it "must handle full_session without error" do
    subject.full_session.must_equal(@full_session)
  end 
end