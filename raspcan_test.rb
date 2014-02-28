#!/usr/bin/env ruby

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
    @data   = data[-8..-1].slice(0,@dlc)
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
class InvalidSdoCommand < StandardError; end

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

  class Func
    attr_reader :data
    def initialize( data )
      @data = data
      @data = @data.unpack("C8") if @data.respond_to?(:unpack)
    end
  end

  class Unknown < Func
    def inspect
      "UNKNOWN"
    end
  end

  class Pdo < Func
    def inspect
      "[PDO]"
    end
  end

  class NmtMc < Func
    COMMANDS = {
        start:     0x01,
        stop:      0x02,
        preop:     0x80,
        reset_app: 0x81,
        reset_com: 0x82
    }

    def command
      data[0]
    end

    def command_
      COMMANDS.invert[command] || raise(InvalidNmtMcCommand.new(command.to_s(16)))
    end

    def node_id
      data[1]
    end

    def inspect
      "[NMT MC #{command_} NODE: 0x#{node_id.to_s(16)}]"
    end

  end

  class Sdo < Func
    SDO_CS_MASK = 0xe0

    SDO_CS_IDD_E_FLAG = 0x02
    SDO_CS_IDD_S_FLAG = 0x01
    SDO_CS_IDD_N_MASK = 0x0c
    SDO_CS_IDD_N_SHIFT = 0x02

    ABORT_CODES = {
      0x05030000 => "Toggle bit not alternated",
      0x05040000 => "SDO protocol timed out",
      0x05040001 => "Client/Server command specifier not valid or unknown",
      0x05040002 => "Invalid block size (Block Transfer mode only)",
      0x05040003 => "Invalid sequence number (Block Transfer mode only)",
      0x05030004 => "CRC error (Block Transfer mode only)",
      0x05030005 => "Out of memory",
      0x06010000 => "Unsupported access to an object",
      0x06010001 => "Attempt to read a write-only object",
      0x06010002 => "Attempt to write a read-only object",
      0x06020000 => "Object does not exist in the Object Dictionary",
      0x06040041 => "Object can not be mapped to the PDO",
      0x06040042 => "The number and length of the objects to be mapped would exceed PDO length",
      0x06040043 => "General parameter incompatibility reason",
      0x06040047 => "General internal incompatibility in the device",
      0x06060000 => "Object access failed due to a hardware error",
      0x06060010 => "Data type does not match, lengh of service parameter does not match",
      0x06060012 => "Data type does not match, lengh of service parameter is too high",
      0x06060013 => "Data type does not match, lengh of service parameter is too low",
      0x06090011 => "Sub-index does not exist",
      0x06090030 => "Value range of parameter exceeded (only for write access)",
      0x06090031 => "Value of parameter written too high",
      0x06090032 => "Value of parameter written too low",
      0x06090036 => "Maximum value is less than minimum value",
      0x08000000 => "General error",
      0x08000020 => "Data can not be transferred or stored to the application",
      0x08000021 => "Data can not be transferred or stored to the application because of local control",
      0x08000022 => "Data can not be transferred or stored to the application because of the present device state",
      0x08000023 => "Object Dictionary dynamic generation fails or no Object Dictionary is present (e.g. OD is generated from file and generation fails because of a file error)",
    }

    COMMAND_DESCRIPTIONS = {
      idd: 'Initiate Domain Download',
      dds: 'Download Domain Segment',
      idu: 'Initiate Domain Upload',
      uds: 'Upload Domain Segment',
      adt: 'Abort Domain Transfer',
      bd:  'Block Download'
    }

    def command
      data[0] & SDO_CS_MASK
    end

    def command_
      raise "abstract method"
    end

    def expedited?
      data[0] & SDO_CS_IDD_E_FLAG
    end

    def size_flag?
      data[0] & SDO_CS_IDD_S_FLAG
    end

    def expedited_size
      # the bits indicate the number of bytes NOT(!) used
      4 - ((data[0] & SDO_CS_IDD_N_MASK) >> SDO_CS_IDD_N_SHIFT)
    end

    def index
      (data[2]<<8)|data[1]
    end

    def sub_index
      data[3]
    end

    def expedited_data
      expedited? ? data[-4..(-5+expedited_size)] : nil
    end

    def abort_code
      (data[7]<<24)|(data[6]<<16)|(data[5]<<8)|(data[4]);
    end

    def abort_code_
      ABORT_CODES[abort_code]
    end

  end

  class SdoRx < Sdo
    COMMANDS = {
      idd: 0x20,
      dds: 0x00,
      idu: 0x40,
      uds: 0x60,
      adt: 0x80,
      bd:  0xC0
    }

    def command_
      COMMANDS.invert[command] || raise(InvalidSdoCommand.new(command.to_s(16)))
    end

    def inspect
      s="SDO RX #{COMMAND_DESCRIPTIONS[command_]||'?'} "

      case command_
        when :idu
          s+="INDEX:0x#{index.to_s(16)} SUBINDEX:#{sub_index} "
        when :idd
          if expedited?
            s+='EXPEDITED '
            if size_flag?
              s+="SIZE:#{ expedited_size } "
            end
            s+="INDEX:0x#{index.to_s(16)} SUBINDEX:#{sub_index} DATA:#{expedited_data.inspect}"
          else
            s+="SEGMENTED SIZE:#{data[2]} "
          end
        when :adt
          s+= abort_code_.inspect
        else
          s+="?"
      end
    end
  end

  class SdoTx < Sdo
    COMMANDS = {
        idd: 0x60,
        dds: 0x20,
        idu: 0x40,
        uds: 0x00,
        adt: 0x80,
        bd:  0xA0
    }

    def command_
      COMMANDS.invert[command] || raise(InvalidSdoCommand.new(command.to_s(16)))
    end

    def inspect
      s="SDO TX #{COMMAND_DESCRIPTIONS[command_]||'?'} "

      case command_
        when :idu
          if expedited?
            s+='EXPEDITED '
            if size_flag?
              s+="SIZE:#{ expedited_size } "
            end
            s+="INDEX:0x#{index.to_s(16)} SUBINDEX:#{sub_index} DATA:#{expedited_data.inspect}"
          else
            s+="SEGMENTED SIZE:#{data[2]} "
          end
        when :idd
          s+="INDEX:0x#{index.to_s(16)} SUBINDEX:#{sub_index} "
        when :adt
          s+= abort_code_.inspect
        else
          s+="?"
      end

      s
    end

  end


  def function_object
    @function_object ||=
      case function_code_
        when :nmt_mc
          NmtMc.new( data )
        when :pdo_1_rx, :pdo_1_tx, :pdo_2_rx, :pdo_2_tx, :pdo_3_rx, :pdo_3_tx, :pdo_4_rx, :pdo_4_tx
          Pdo.new( data )
        when :sdo_rx
          SdoRx.new( data )
        when :sdo_tx
          SdoTx.new( data )
        else
          Unknown.new( data )
      end
  end

  def inspect
    if standard?
      "<CanOpenFrame: FC:0x#{function_code.to_s(16)}:#{function_code_} ID:0x#{node_id.to_s(16)} #{rtr? ? 'RTR ':' '}D:#{dlc}:#{data.map { |d| d.to_s(16).rjust(2,'0') }.join('.')} => #{function_object.inspect}>"
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
  printf("%s %s\n",Time.now, cof.inspect)
end




