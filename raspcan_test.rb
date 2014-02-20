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

  def node_id
    can_id && ( eff? ? CAN_EFF_MASK : CAN_SFF_MASK )
  end
end

class CanOpenFrame < CanFrame
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
  puts cf.node, cf.inspect
  puts cof.inspect
  prev = now
  #can_frame = CanFrame.read(socket)
  #p can_frame
end




