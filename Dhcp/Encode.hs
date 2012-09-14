module Dhcp.Encode where

import Data.Binary
import Data.Binary.Put
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toChunks)
import Dhcp.Types
import Data.List
import Data.Maybe
import Data.Word
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL

encodeReply :: DhcpReply -> ByteString
encodeReply (OFFER header yiaddr options) = encodeDhcpBootp header 2 ciaddr yiaddr siaddr options'
    where
        ciaddr = IPv4 0
        siaddr = IPv4 0
        options' = (MessageType TOffer) : options
encodeReply (ACK header yiaddr options) = encodeDhcpBootp header 2 ciaddr yiaddr siaddr options'
    where
        ciaddr = IPv4 0
        siaddr = IPv4 0
        options' = (MessageType TAck) : options
encodeReply (NAK header) = encodeDhcpBootp header 2 ciaddr yiaddr siaddr options
    where
        ciaddr = IPv4 0
        siaddr = IPv4 0
        yiaddr = IPv4 0
        options = [MessageType TNAck]


{-
encodeDhcp :: BootPacket -> ByteString
encodeDhcp (DhcpDecline header) =  -- {{{
        encodeDhcpBootp header 1 ciaddr' yiaddr' siaddr' options'
    where
        ciaddr' = IPv4 0
        yiaddr' = IPv4 0
        siaddr' = IPv4 0
        options' = [MessageType Decline]
-- }}}
encodeDhcp (DhcpRelease header ciaddr) =  -- {{{
        encodeDhcpBootp header 1 ciaddr yiaddr' siaddr' options'
    where
        yiaddr' = IPv4 0
        siaddr' = IPv4 0
        options' = [MessageType Release]
-- }}}
encodeDhcp (DhcpInform header ciaddr options) =  -- {{{
        encodeDhcpBootp header 1 ciaddr yiaddr' siaddr' options'
    where
        yiaddr' = IPv4 0
        siaddr' = IPv4 0
        options' = MessageType Release : options
-- }}}
encodeDhcp (DhcpDiscover header ciaddr options) =  -- {{{
        encodeDhcpBootp header 1 ciaddr' yiaddr' siaddr' options'
    where
        ciaddr' = maybe (IPv4 0) id ciaddr
        yiaddr' = IPv4 0
        siaddr' = IPv4 0
        options' = (MessageType Discover) : options
-- }}}
encodeDhcp (DhcpRequest header ciaddr options) =  -- {{{
        encodeDhcpBootp header 1 ciaddr' yiaddr' siaddr' options'
    where
        ciaddr' = maybe (IPv4 0) id ciaddr
        yiaddr' = IPv4 0
        siaddr' = IPv4 0
        options' = (MessageType Request) : options
-- }}}
encodeDhcp (DhcpNAck header) = -- {{{
        encodeDhcpBootp header 2 ciaddr' yiaddr' siaddr' options'
    where
        ciaddr' = IPv4 0
        yiaddr' = IPv4 0
        siaddr' = IPv4 0
        options' = [End]
-- }}}
encodeDhcp (DhcpAck header ciaddr yiaddr siaddr options) = -- {{{
        encodeDhcpBootp header 2 ciaddr' yiaddr siaddr' options'
    where        
        ciaddr' = maybe (IPv4 0) id ciaddr
        siaddr' = maybe (IPv4 0) id siaddr
        options' = (MessageType Ack) : options
-- }}}
-}

encodeDhcpBootp :: BootpHeader -> Word8 -> IP -> IP -> IP -> [DhcpOption] -> ByteString
encodeDhcpBootp h op ciaddr yiaddr siaddr options = B.concat . toChunks . runPut $ do
        putHeader op h
        putWord16be 0 -- seconds
        if (h_flag h)
            then putWord8 0x80 >> putWord8 0x00
            else putWord8 0x00 >> putWord8 0x00

        put ciaddr >> put yiaddr >> put siaddr >> put giaddr

        put (h_mac h)
        putByteString (B.replicate 64 0)  -- sname
        putByteString (B.replicate 128 0) -- filename
        
        putDhcpMagic
        mapM_ put options
        put End
    where
        giaddr = maybe (IPv4 0) id . h_gw $ h

putHeader :: Word8 -> BootpHeader -> Put
putHeader op h = putWord8 op >> put (h_hw h) >> put (h_hops h) >> putWord32be (h_xid h)


putMIP :: Maybe IP -> Put
putMIP (Just (IPv4 ip)) = putWord32be ip
putMIP Nothing = putWord32be 0

putDhcpMagic :: Put
putDhcpMagic = mapM_ putWord8 [99, 130, 83, 99]


instance Binary Hardware where
    put (Hardware h l) = putWord8 h >> putWord8 l
    get = undefined

instance Binary Mac where
    put mac = mapM_ putWord8 (decodeMac mac) >> mapM_ putWord8 (replicate 10 0)
    get = undefined

instance Binary IP where
    put (IPv4 ip) = putWord32be ip
    get = undefined

instance Binary DhcpOption where
    put Padding                = putWord8    0
    put (SubnetMask ip)        = putTagged   1 (put ip)
    put (RouterOption ips)     = putTagged   3 (mapM_ put ips)
    put (DomainNameServer ips) = putTagged   6 (mapM_ put ips)
    put (HostName h)           = putTagged  12 (putByteString h)
    put (DomainName d)         = putTagged  15 (putByteString d)
    put (DoRouterDiscovery b)  = putTagged  31 (putWord8 $ if b then 1 else 0)
    put (StaticRoute rs)       = putTagged  33 (mapM_ (\(d, r) -> put d >> put r) rs)
    put (VendorSpecific vs)    = putTagged  43 (putByteString vs)
    put (RequestedAddress ip)  = putTagged  50 (put ip)
    put (LeaseTime t)          = putTagged  51 (putWord32be t)
    put (OptionOverload loc)   = putTagged  52 (put loc)
    put (MessageType t)        = putTagged  53 (put t)
    put (ServerID ip)          = putTagged  54 (put ip)
    put (RequestedParams ps)   = putTagged  55 (mapM_ put ps)
    put (Message m)            = putTagged  56 (putByteString m)
    put (VendorID vendor)      = putTagged  60 (putByteString vendor)
    put (ClientID client)      = putTagged  61 (putByteString client)
    put (FQDN flag host)       = putTagged  81 (putWord8 flag >> putWord8 255 >> putWord8 255 >> putByteString host)
    put (RelayAgent r)         = putTagged  82 (mapM_ put r)




    put End                   = putWord8 255
    put (UnknownOption t v)   = putTagged t (putByteString v)
    get = undefined

instance Binary OverloadLocation where
    put (OverloadFile)        = putWord8 1
    put (OverloadSname)       = putWord8 2
    put (OverloadBoth)        = putWord8 3
    get = undefined

instance Binary AgentOption where
    put (AgentCircuitID cid) = putTagged 1 (putByteString cid)
    put (AgentRemoteID rid)  = putTagged 2 (putByteString rid)
    get = undefined

instance Binary MsgType where
    put = putWord8 . fromIntegral . (+1) . fromJust . flip elemIndex [TDiscover, TOffer, TRequest, TDecline, TAck, TNAck, TRelease, TInform]
    get = undefined


putTagged :: Word8 -> Put -> Put
putTagged tag v = do 
        putWord8 tag
        putWord8 (fromIntegral $ BL.length value)
        putLazyByteString value
    where
        value = runPut v
