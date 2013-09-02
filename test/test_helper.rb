require 'minitest/spec'
require 'minitest/autorun'
require 'minitest/pride'
require File.expand_path('../../lib/spcap.rb', __FILE__)
Spcap::Logger.level=Log4r::DEBUG