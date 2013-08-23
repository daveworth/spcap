module Spcap
  Logger = Log4r::Logger.new 'spcap_logger'
  Logger.outputters = Log4r::Outputter.stderr
  Logger.level=Log4r::INFO
end
