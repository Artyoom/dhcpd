module Dhcp.Decode where

import Control.Applicative
import Data.Attoparsec as A
import Data.ByteString (ByteString)
import Dhcp.Types
-- import Data.IP
import Data.List
import Data.Word
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8

-- Discover, request, decline, release

decodeRequest :: ByteString -> Maybe DhcpRequest
decodeRequest msg = maybeResult $ feed (parse requestParser msg) B.empty

requestParser :: Parser DhcpRequest
requestParser = do
        word8 0x01
        hw <- hardware

        hops <- anyWord8
        xid <- parseWord32
        secs <- parseWord16
        flags <- parseFlags

        ciaddr <- parseIP
        yiaddr <- parseIP
        siaddr <- parseIP
        giaddr <- parseIP

        chaddr <- parseMac
        sname <- A.take 64
        file <- A.take 128
        dhcpMagic


        let header = BootpHeader hw xid giaddr hops flags chaddr


        options <- allDhcpOptions sname file
        case (getMessageType options) of
            (Just TDiscover)-> return $ DISCOVER header ciaddr options

            (Just TRequest) -> return $ REQUEST  header ciaddr options

            (Just TDecline) -> return $ DECLINE header 

            (Just TRelease) -> case ciaddr of
                 (Just ip) -> return $ RELEASE --header ip
                 (Nothing) -> fail "No ciaddr IP address given in DHCPRELEASE"

            (Just TInform)  -> case ciaddr of
                    (Just ip) -> return $ INFORM --header ip options
                    (Nothing) -> fail "No IP address given in DHCPINFORM"

            (Just TOffer)  -> fail "Invalid request value."
            (Just TAck)    -> fail "Invalid request value."
            (Just TNAck)   -> fail "Invalid request value."


            Nothing -> fail "Invalid request value." 


parseFlags = (True <$ word8 0x80 <* word8 0x00) <|> (False <$ word8 0x00 <* word8 0x00)


{-

decodeDhcp :: ByteString -> Either String BootPacket
decodeDhcp packet = eitherResult $ feed (parse dhcp packet) B.empty

dhcp :: Parser BootPacket
dhcp = do 
        op <- (word8 0x01 <|> word8 0x02)
        hw <- hardware
        hops <- anyWord8
        xid <- parseWord32
        secs <- parseWord16
        flags <- (True <$ word8 0x80 <* word8 0x00) <|> (False <$ word8 0x00 <* word8 0x00)

        ciaddr <- parseIP
        yiaddr <- parseIP
        siaddr <- parseIP
        giaddr <- parseIP

        chaddr <- parseMac hw
        sname <- A.take 64
        file <- A.take 128

        dhcp <- (True <$ dhcpMagic) <|> (return False)

        let header = BootpHeader hw xid giaddr hops flags chaddr

        if dhcp
            then do options <- allDhcpOptions sname file
                    case (op, getMessageType options) of
                        (1, Just Discover)-> return $ DhcpDiscover header ciaddr options

                        (1, Just Request) -> return $ DhcpRequest header ciaddr options

                        (1, Just Decline) -> return $ DhcpDecline header 

                        (1, Just Release) -> case ciaddr of
                                (Just ip) -> return $ DhcpRelease header ip
                                (Nothing) -> fail "No ciaddr IP address given in DHCPRELEASE"

                        (1, Just Inform)  -> case ciaddr of
                                (Just ip) -> return $ DhcpInform header ip options
                                (Nothing) -> fail "No IP address given in DHCPINFORM"

                        (2, Just Offer)   -> case ((,) <$> yiaddr <*> ciaddr) of
                                (Just (yi, ci)) -> return $ DhcpOffer header yi ci options
                                (Nothing)       -> fail "yiaddr or ciaddr was not specified in DHCPOFFER packet)"

                        (2, Just Ack)     -> case yiaddr of
                                (Just ip) -> return $ DhcpAck header ciaddr ip siaddr options
                                (Nothing) -> fail "No yiaddr IP address given in DHCPACK"

                        (2, Just NAck)    -> return $ DhcpNAck header 

                        (_, Nothing)      -> fail "No DHCP Message type was given in DHCP Options"
                        (1, _)            -> fail "Invalid message op code: BOOTPREQUEST, but it must me BOOTPREPLY"
                        (_, _)            -> fail "Invalid message op code: BOOTPREPLY, but it must me BOOTPREQUEST"

                    
            else do options <- vendorOptions 
                    case op of
                        0x01 -> return $ BootRequest header ciaddr sname options
                        0x02 -> case ((,) <$> yiaddr <*> siaddr) of
                            (Just (yi, si)) -> return $ BootReply header yi si sname file options
                            (Nothing)       -> fail "No yiaddr or siaddr was given in BOOTPREPLY"
                        _    -> fail "lolwut? O_o"
-}

--vendorOptions :: Parser BootVend
--vendorOptions = BootVend <$> A.takeWhile (const True)

allDhcpOptions :: ByteString -> ByteString -> Parser [DhcpOption]
allDhcpOptions sname file = do
        main_options <- cleanOptions <$> A.many dhcpOption
        overloaded_options <- case (getOptionOverload main_options) of
            (Just OverloadFile) -> cleanOptions <$> parseOptions file
            (Just OverloadSname) -> cleanOptions <$> parseOptions sname
            (Just OverloadBoth) -> (++) <$> (cleanOptions <$> parseOptions file) <*> (cleanOptions <$> parseOptions sname)
            Nothing -> return []

        return $ main_options ++ overloaded_options


dhcpOption :: Parser DhcpOption
dhcpOption = (A.choice possibleOptions <|> unknownOption)
    where
        unknownOption = UnknownOption <$> A.anyWord8 <*> (A.anyWord8 >>= A.take . fromIntegral)
        possibleOptions = [pad, overload, msgtype, requested_address, requested_params, relay_agent, 
                server_id, client_id, vendor_id, hostname, fqdn, end]

        pad = Padding <$ A.word8 0

        hostname = HostName <$> (word8 12 *> anyWord8 >>= A.take . fromIntegral)


        requested_address = (RequestedAddress . IPv4) <$> (word8 50 *> word8 4 *> parseWord32)

        requested_params = (RequestedParams . B.unpack) <$> (word8 55 *> A.anyWord8 >>= A.take . fromIntegral)

        overload = OptionOverload <$> (word8 52 *> word8 1 *> ((OverloadFile  <$ word8 1) 
                                                           <|> (OverloadSname <$ word8 2)
                                                           <|> (OverloadBoth  <$ word8 3)))


        msgtype = MessageType <$> (word8 53 *> word8 1 *> ((TDiscover <$ word8 1)
                                                       <|> (TOffer    <$ word8 2)
                                                       <|> (TRequest  <$ word8 3)
                                                       <|> (TDecline  <$ word8 4)
                                                       <|> (TAck      <$ word8 5)
                                                       <|> (TNAck     <$ word8 6)
                                                       <|> (TRelease  <$ word8 7)
                                                       <|> (TInform   <$ word8 8)))

        
        server_id = (ServerID . IPv4) <$> (word8 54 *> word8 4 *> parseWord32)

        vendor_id = VendorID <$> (word8 60 *> anyWord8 >>= A.take . fromIntegral)
            
        client_id = ClientID <$> (word8 61 *> anyWord8 >>= A.take . fromIntegral)

        fqdn = word8 81 *> anyWord8 >>= extractFQDN
            where
                extractFQDN :: Word8 -> Parser DhcpOption
                extractFQDN l = do
                        raw <- A.take $ fromIntegral l
                        case (eitherResult $ feed (parse (FQDN <$> (anyWord8 <* anyWord8 <* anyWord8) <*> A.takeWhile (const True)) raw) B.empty) of
                            (Right v) -> return v
                            (Left e)  -> fail e

        relay_agent = RelayAgent <$> (word8 82 *> anyWord8 >>= extractRelayAgent)
            where
                extractRelayAgent :: Word8 -> Parser [AgentOption]
                extractRelayAgent l = do 
                        raw <- A.take $ fromIntegral l
                        case (eitherResult $ feed (parse (A.many1 agentOption) raw) B.empty) of
                            (Right v) -> return v
                            (Left e)  -> fail e

                agentOption :: Parser AgentOption
                agentOption = circuitID <|> remoteID

                circuitID = AgentCircuitID <$> (word8 1 *> anyWord8 >>= A.take . fromIntegral)
                remoteID = AgentRemoteID <$> (word8 2 *> anyWord8 >>= A.take . fromIntegral)



        end = End     <$ A.word8 255



parseOptions :: ByteString -> Parser [DhcpOption]
parseOptions s = 
        case (feed (parse (A.many dhcpOption) s) B.empty) of
            (Done _ result) -> return result
            (Fail _ _ e)    -> fail e
            (Partial _)     -> fail "WTF!?"

cleanOptions :: [DhcpOption] -> [DhcpOption]
cleanOptions = (filter (/= Padding)) . (Prelude.takeWhile (/= End))

getOptionOverload :: [DhcpOption] -> Maybe OverloadLocation
getOptionOverload = fmap (\(OptionOverload o) -> o) . find overload
    where
        overload (OptionOverload _) = True
        overload _ = False

getMessageType :: [DhcpOption] -> Maybe MsgType
getMessageType = fmap (\(MessageType x) -> x) . find msgtype
    where
        msgtype (MessageType _) = True
        msgtype _ = False



hardware :: Parser Hardware
hardware = Hardware <$> anyWord8 <*> anyWord8

dhcpMagic :: Parser ByteString
dhcpMagic = string . B.pack $ [99, 130, 83, 99]

parseMac :: Parser Mac
parseMac = (mkMac . B.unpack) <$> (A.take 6) <* (A.take 10)

parseIP :: Parser (Maybe IP)
parseIP = do 
        ip <- parseWord32
        return $ case ip of
            0 -> Nothing
            x -> Just $ IPv4 x

parseWord16 :: Parser Word16
parseWord16 = collectInt <$> A.take 2

parseWord32 :: Parser Word32
parseWord32 = collectInt <$> A.take 4

collectInt :: (Num a) => ByteString -> a
collectInt = B.foldl (\i b -> i * 256 + fromIntegral b) 0


msg0 = "\SOH\SOH\ACK\SOH\a\SI\137h\NUL\NUL\128\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\n\a\v\SOH\FS\189\185+\250\ETX\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NUL\NULc\130Sc5\SOH\SOH=\a\SOH\FS\189\185+\250\ETX\f\aDIR-3002\EOT\n\a\v\246\&7\t\SOH\ETX\ACK\SI!,./yR\DC2\SOH\ACK\NUL\EOT\NUL\SOH\NUL\STX\STX\b\NUL\ACK\NUL\NAK\233DBw\255"
