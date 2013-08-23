require_relative '../../test_helper'
 
describe Spcap::File do
  subject { Spcap::File.new(File.open('test/pcap_files/sample.pcap'))  }
  
  it "must be a Spcap::File" do
    subject.must_be_instance_of(Spcap::File)
  end
  
  it "must handle each without error" do
    subject.each{|p| }
    subject.must_respond_to(:each)
  end

end
