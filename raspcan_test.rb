require 'rubygems'
require 'bundler/setup'

require 'bindata'
require 'eventmachine'

require 'socket'
require_relative './can_open'

puts "Version #{CanOpen::VERSION} Platform "+ RUBY_PLATFORM

PF_CAN=29
AF_CAN=PF_CAN
CAN_RAW=1
SIOCGIFINDEX=0x8933

class Ifreq < BinData::Record
  endian :little
  string :name, :length => 16
  int32  :ifindex
end

class SockaddrCan < BinData::Record
  endian :little
  uint16  :family
  int32  :ifindex
  struct :addr do
    uint32 :rx_id
    uint32 :tx_id
  end
  uint16 :dummy  # 16 byte alignment
end

class CanFrame < BinData::Record
  endian :little
  uint32 :can_id
  uint8  :dlc
  array  :dummy1, :type => :uint8, :initial_length => 3
  array  :data,   :type => :uint8, :initial_length => 8

  CAN_EFF_FLAG = 0x80000000
  CAN_RTR_FLAG = 0x40000000
  CAN_ERR_FLAG = 0x20000000

  CAN_SFF_MASK = 0x000007FF
  CAN_EFF_MASK = 0x1FFFFFFF
  CAN_ERR_MASK = 0x1FFFFFFF

  def err?
    (can_id & CAN_ERR_FLAG) == CAN_ERR_FLAG
  end

  def eff?
    (can_id & CAN_EFF_FLAG) == CAN_EFF_FLAG
  end

  def standard?
    ! eff?
  end

  def rtr?
    (can_id & CAN_RTR_FLAG) == CAN_RTR_FLAG
  end

  def node_id
    can_id & ( eff? ? CAN_EFF_MASK : CAN_SFF_MASK )
  end

  def inspect
    "<CanFrame: ID:0x#{node_id.to_s(16)} DLC:#{dlc} DATA:#{data.inspect} >"
  end
end

class InvalidFunctionCode < StandardError; end

class CanOpenFrame < CanFrame

  FUNCTION_CODES = {
    unknown:   nil,
    nmt_mc:    0x00,
    emergency: 0x01,
    sync:      0x01,
    timestamp: 0x02,
    pdo_1_tx:  0x03,
    pdo_1_rx:  0x04,
    pdo_2_tx:  0x05,
    pdo_2_rx:  0x06,
    pdo_3_tx:  0x07,
    pdo_3_rx:  0x08,
    pdo_4_tx:  0x09,
    pdo_4_rx:  0x0a,
    sdo_tx:    0x0b,
    sdo_rx:    0x0c,
    nmt_ng:    0x0e
  }

  NMT_MC = {
    start:     0x01,
    stop:      0x02,
    preop:     0x80,
    reset_app: 0x81,
    reset_com: 0x82
  }

  NMT_NG = {
    bootup:         0x00,
    disconnected:   0x01,
    connected:      0x02,
    preparing:      0x03,
    stopped:        0x04,
    operational:    0x05,
    preoperational: 0x7F
  }

  def function_code
    standard? ? ((can_id & 0x00000780) >> 7) : nil
  end

  def function_code?( code_or_symbol )
    if code_or_symbol.is_a?(Symbol)
      function_code_ == code_or_symbol
    else
      function_code == code_or_symbol
    end
  end

  FUNCTION_CODES.keys.each do |code|
    define_method :"#{code}?" do
      function_code?(code)
    end
  end

  def function_code_
    FUNCTION_CODES.invert[function_code] || raise(InvalidFunctionCode.new(function_code.to_s(16)))
  end

  def node_id
    standard? ? (can_id & 0x0000007F) : node_id
  end

  def inspect
    if standard?
      "<CanOpenFrame: FC:0x#{function_code.to_s(16)}:#{function_code_} ID:0x#{node_id.to_s(16)} #{rtr? ? 'RTR ':' '}DLC:#{dlc} DATA:#{data.inspect}>"
    else
      "<CanOpenFrame: EXTENDED ID:0x#{node_id.to_s(16)} "
    end
  end

end

interface = 'can0'

socket = Socket.open(PF_CAN, Socket::SOCK_RAW, CAN_RAW)

# struct ifreq in net/if.h
ifreq= Ifreq.new :name => interface
socket.ioctl(SIOCGIFINDEX, ifreq.to_binary_s)

addr = SockaddrCan.new(:family => AF_CAN, :ifindex => ifreq.ifindex)

addr.to_binary_s.length
socket.bind(addr.to_binary_s)

puts "Waiting..."
prev = nil
while true do
  data = socket.read(16)
  cof = CanOpenFrame.read(data)
  cf = CanFrame.read(data)
  now = Time.now.to_f
  puts now, (now - (prev||0)), data.unpack('H*')[0]
  p cf
  p cof
  p cof.sdo_tx?
  p cof.sdo_rx?
  prev = now
  #can_frame = CanFrame.read(socket)
  #p can_frame
end




