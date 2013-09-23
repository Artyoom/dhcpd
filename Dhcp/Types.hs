module Dhcp.Types where

import Data.Bits
import Data.ByteString (ByteString)
import Data.List
import Data.Word
import Network.Socket (HostAddress)
import Numeric (showHex)


data BootpHeader
    = BootpHeader
    { h_hw   :: Hardware   -- ^ Hardware specification
    , h_xid  :: Word32     -- ^ xid
    , h_gw   :: (Maybe IP) -- ^ gateway address, if any
    , h_hops :: Word8      -- ^ number of hops
    , h_flag :: Bool       -- ^ broadcast flag
    , h_mac  :: Mac        -- ^ user mac address
    }
    deriving (Show, Eq, Ord)


data Hardware = Hardware Word8 Word8 -- hw id and mac size
    deriving (Show, Eq, Ord)

data IP = IPv4 Word32 deriving (Eq, Ord)
--      | IPv6 Word32 Word32 Word32 Word32
data Dhcp
    = Request DhcpRequest
    | Reply DhcpReply
    deriving (Show, Eq, Ord)

data DhcpRequest
    = DISCOVER BootpHeader
          (Maybe IP)         -- ^ ip address, if user wants something specific
          [DhcpOption]       -- ^ Set of DHCP options

    | REQUEST BootpHeader
          (Maybe IP)         -- ^ ip address, if user wants something specific
          [DhcpOption]
    | DECLINE BootpHeader
    | RELEASE
    | INFORM
    deriving (Show, Eq, Ord)

data DhcpReply
    = OFFER BootpHeader
          IP               -- ^ IP address offered to client
          [DhcpOption]
    | ACK BootpHeader
          IP
          [DhcpOption]
    | NAK BootpHeader
--          IP
--          [DhcpOption]
    deriving (Show, Eq, Ord)

data DhcpLease
    = DhcpLease
    { dl_relay   :: Maybe HostAddress
    , dl_router  :: IP
    , dl_dns     :: IP
    , dl_circuit :: Maybe ByteString
    , dl_remote  :: Maybe ByteString
    , dl_mac     :: Maybe Mac
    , dl_client  :: IP
    , dl_mask    :: Word8
    } deriving (Show, Eq, Ord)


data MsgType
    = TDiscover
    | TOffer
    | TRequest
    | TAck
    | TNAck
    | TDecline
    | TRelease
    | TInform
    deriving (Show, Eq, Ord)
    
data OverloadLocation
    = OverloadFile
    | OverloadSname
    | OverloadBoth
    deriving (Show, Eq, Ord)
    
data AgentOption
    = AgentCircuitID ByteString
    | AgentRemoteID ByteString
    deriving (Show, Eq, Ord)
    
data DhcpOption
    = Padding                               -- option 0
    | SubnetMask IP                         -- option 1   _
    | RouterOption [IP]                     -- option 3   _
    | DomainNameServer [IP]                 -- option 6   _
    | HostName ByteString                   -- option 12  _
    | DomainName ByteString                 -- option 15  _
    | DoRouterDiscovery Bool                -- option 31  _
    | StaticRoute [(IP, IP)]                -- option 33  _ <Classfull static routes>, the network mask is deducted according IETF RFQs.
    | VendorSpecific ByteString             -- option 43  _
    | RequestedAddress IP                   -- option 50
    | LeaseTime Word32                      -- option 51
    | OptionOverload OverloadLocation       -- option 52
    | MessageType MsgType                   -- option 53
    | ServerID IP                           -- option 54
    | RequestedParams [Word8]               -- option 55
    | Message ByteString                    -- option 56  _
    | VendorID ByteString                   -- option 60
    | ClientID ByteString                   -- option 61  _
    | FQDN Word8 ByteString                 -- option 81
    | RelayAgent [AgentOption]              -- option 82  _
    | End                                   -- option 255
    | UnknownOption Word8 ByteString        -- this option not implemented yet
    deriving (Show, Eq, Ord)


data Mac = Mac (Word8, Word8, Word8, Word8, Word8, Word8) deriving (Eq, Ord)


instance Show (Mac) where
    show = showMac


nextIP :: IP -> IP
nextIP (IPv4 i) = IPv4 . succ $ i

addToIP :: Integral a => a -> IP -> IP
addToIP c (IPv4 i) = IPv4 $ i + (fromIntegral c)

mkMac :: [Word8] -> Mac
mkMac ([o1,o2,o3,o4,o5,o6]) = Mac (o1,o2,o3,o4,o5,o6)
mkMac _ = error "Invalid mac address"

decodeMac :: Mac -> [Word8]
decodeMac (Mac (o1,o2,o3,o4,o5,o6)) = [o1,o2,o3,o4,o5,o6]

showMac :: Mac -> String
showMac (Mac (o1,o2,o3,o4,o5,o6)) = intercalate ":" . map (flip showHex "") $ [o1,o2,o3,o4,o5,o6]


instance Show (IP) where
    show = showIP

mkIP :: Word8 -> Word8 -> Word8 -> Word8 -> IP
mkIP o1 o2 o3 o4 = IPv4 $ (fromIntegral o1) * 2^24 + (fromIntegral o2) * 2^16 + (fromIntegral o3) * 2^8 + (fromIntegral o4)

showIP :: IP -> String
showIP (IPv4 ip) = (intercalate "." . map show)  [o1, o2, o3, o4]
    where
        o1 = (ip .&. 0xFF000000) `shiftR` 24
        o2 = (ip .&. 0x00FF0000) `shiftR` 16
        o3 = (ip .&. 0x0000FF00) `shiftR` 8
        o4 = (ip .&. 0x000000FF)
