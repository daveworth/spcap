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
