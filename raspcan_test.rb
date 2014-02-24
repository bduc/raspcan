require 'rubygems'
require 'bundler/setup'

require 'eventmachine'

require 'socket'
require_relative './can_open'

puts "Version #{CanOpen::VERSION} Platform "+ RUBY_PLATFORM

class CanSocket < Socket

  PF_CAN=29
  AF_CAN=PF_CAN
  CAN_RAW=1
  SIOCGIFINDEX=0x8933

  def initialize( can_interface_name )

    super(PF_CAN, Socket::SOCK_RAW, CAN_RAW)

    #socket = Socket.open(PF_CAN, Socket::SOCK_RAW, CAN_RAW)

    # struct ifreq in net/if.h
    if_idx_req = can_interface_name.ljust(16,"\0")+[0].pack("L")
    ioctl(SIOCGIFINDEX, if_idx_req )

    if_name,if_index = if_idx_req.unpack("A16L")

    # sockaddr_can from linux/can.h
    #struct sockaddr_can {
    #  __kernel_sa_family_t can_family;                                     S
    #  int         can_ifindex;                                             l
    #  union {
    #    /* transport protocol class address information (e.g. ISOTP) */
    #    struct { canid_t rx_id, tx_id; } tp;                               LL
    #
    #    /* reserved for future CAN protocols address information */
    #  } can_addr;
    #};
    # align on 16 byte -> pad with 2 bytes exta                             S

    sockaddr_can = [AF_CAN,if_index,0,0,0].pack("SlLLS")

    bind(sockaddr_can)
  end

end


class InvalidFunctionCode < StandardError; end

class CanFrame
  attr_reader :can_id, :dlc, :data

  CAN_EFF_FLAG = 0x80000000
  CAN_RTR_FLAG = 0x40000000
  CAN_ERR_FLAG = 0x20000000

  CAN_SFF_MASK = 0x000007FF
  CAN_EFF_MASK = 0x1FFFFFFF
  CAN_ERR_MASK = 0x1FFFFFFF

  def initialize( data_frame = nil )
    if data_frame
      raise InvalidFrameLength.new(data_frame.size) unless data_frame.size == 16
    end
    data = data_frame.unpack("LCC3C8")

    @can_id = data[0]
    @dlc    = data[1]
    @data   = data[-8..-1]
  end


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
class InvalidNmtMcCommand < StandardError; end

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

  class Unknown
    def initialize( data )
      @data = data
    end
    def inspect
      "UNKNOWN"
    end
  end

  class NmtMc
    COMMANDS = {
        start:     0x01,
        stop:      0x02,
        preop:     0x80,
        reset_app: 0x81,
        reset_com: 0x82
    }

    def initialize( data )
      @data = data
      @data = @data.unpack("C8") if @data.respond_to?(:unpack)
    end

    def command
      @data[0]
    end

    def command_
      COMMANDS.invert[command] || raise(InvalidNmtMcCommand.new(command.to_s(16)))
    end

    def node_id
      @data[1]
    end

    def inspect
      "NMT MC #{command_} NODE: 0x#{node_id.to_s(16)}"
    end

  end

  def function_object
    case function_code_
      when :nmt_mc
        NmtMc.new( data )
      else
        Unknown.new( data )
    end
  end

  def inspect
    if standard?

      function_details = function_object.inspect

      "<CanOpenFrame: FC:0x#{function_code.to_s(16)}:#{function_code_} ID:0x#{node_id.to_s(16)} #{rtr? ? 'RTR ':' '}DLC:#{dlc} DATA:#{data.inspect} #{function_object.inspect}>"
    else
      "<CanOpenFrame: EXTENDED ID:0x#{node_id.to_s(16)} "
    end
  end

end

socket = CanSocket.new( 'can0' )

puts "Waiting..."
prev = nil
while true do
  data = socket.read(16)
  cof = CanOpenFrame.new(data)
  now = Time.now.to_f
  puts now, (now - (prev||0)), data.unpack('H*')[0]
  p cof
  p cof.sdo_tx?
  p cof.sdo_rx?
  prev = now
end




