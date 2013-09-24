{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module Dhcp.Config ( getLeases
                   , initLeases
                   ) where

import Control.Applicative
import Control.Concurrent.STM
import Control.Concurrent.STM.TVar
import Data.Attoparsec as A
import Data.Attoparsec.Char8 (decimal, isSpace_w8, space, char, peekChar)
import Data.Bits
import Data.ByteString (ByteString)
import Data.Char
import Data.Map (Map)
import Data.Word
import Dhcp.Types
import Network.Socket
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.Map as M

type LeaseDB = [DhcpLease]
type TokenMap = Map ByteString ByteString

getLeases :: IO (TVar (Map ByteString DhcpLease))
getLeases = undefined
{-    newTVarIO
-}

initLeases :: IO LeaseDB
initLeases = do
        file <- B.readFile "dhcp.conf"
        case (feed (parse leasesLines file) B.empty) of
            Partial _ -> error "Error in attoparsec"
            Done rest result -> if (B.null rest) then return result else (error $ "unparsed tail: " ++ show rest)
            Fail _ _ msg -> error $ "Failed to read dhcp.conf: " ++ msg

leasesLines :: Parser [DhcpLease]
leasesLines = concat <$> leases `sepBy` A.takeWhile1 (inClass "\n\r") <* A.takeWhile1 (inClass "\r\n")

leases :: Parser [DhcpLease]
leases = lease_dlink <|> lease_raw <|> lease_edge

tokenMap :: Parser TokenMap
tokenMap = M.fromList <$> tokenPair `sepBy` blank
    where
        tokenPair :: Parser (ByteString, ByteString)
        tokenPair = (,) <$> A.takeWhile1 (notInClass ":") <* char ':' <*> A.takeWhile1 (notInClass " \t\n\r")

fparse :: Parser a -> ByteString -> a
fparse p bs = case parseOnly p bs of
                Right r -> r
                Left e -> error $ "Failed to parse " ++ show bs


findTokenMap :: TokenMap -> ByteString -> Parser a -> a
findTokenMap tm bs p = fparse p $ M.findWithDefault e bs tm
    where
        e = error $ "Must specify " ++ show bs

lookupTokenMap :: TokenMap -> ByteString -> Parser a -> Maybe a
lookupTokenMap tm bs p = fparse p <$> M.lookup bs tm

lease_dlink :: Parser[DhcpLease]
lease_dlink = do
    string "dlink" <* blank
    tmap <- tokenMap
    let relay  = i2h <$> lookupTokenMap tmap "ip" ip
        remote = lookupTokenMap tmap "remote" rawhex
        mac    = lookupTokenMap tmap "mac" hexmac
        vlan   = findTokenMap tmap "vlan" decimal
        router = findTokenMap tmap "gw" ip
        dns    = findTokenMap tmap "dns" ip
        ports  = findTokenMap tmap "ports" portSpec
        (base, mask) = findTokenMap tmap "base" ((,) <$> ip  <* char '/' <*> decimal)

    return $ zipWith (mkLeaseDlink mac relay remote router dns vlan mask) ports (zipWith addToIP (map pred ports) (repeat base))

lease_edge :: Parser [DhcpLease]
lease_edge = do
    string "edge" <* blank
    tmap <- tokenMap
    let remote = lookupTokenMap tmap "remote" rawhex
        vlan   = findTokenMap tmap "vlan" decimal
        router = findTokenMap tmap "gw" ip
        mac    = lookupTokenMap tmap "mac" hexmac
        dns    = findTokenMap tmap "dns" ip
        ports  = findTokenMap tmap "ports"  portSpec
        (base, mask) = findTokenMap tmap "base" ((,) <$> ip  <* char '/' <*> decimal)
    return $ zipWith (mkLeaseEdge mac router remote dns vlan mask) ports (zipWith addToIP (map pred ports) (repeat base))

lease_raw :: Parser [DhcpLease]
lease_raw = do
    string "raw82" <* blank
    tmap <- tokenMap
    let circuit = lookupTokenMap tmap "circuit" rawhex
        remote  = lookupTokenMap tmap "remote" rawhex
        mac     = lookupTokenMap tmap "mac" hexmac
        router = findTokenMap tmap "gw" ip
        dns    = findTokenMap tmap "dns" ip
        (client, mask) = findTokenMap tmap "client" ((,) <$> ip  <* char '/' <*> decimal)
    return [mkLeaseRaw mac circuit remote router dns mask client]


rawhex :: Parser ByteString
rawhex = do
    c <- peekChar
    case c of
        Just c | c `elem` "\t " -> return B.empty
        Just c -> do
                c1 <- anyWord8
                c2 <- anyWord8
                rest <- rawhex
                return $ B.cons (16 * (hex2dec c1) + hex2dec c2) rest
        _ -> return B.empty

hexmac :: Parser Mac
hexmac = (mkMac . B.unpack) <$> rawhex

hex2dec :: Word8 -> Word8
hex2dec c = case () of
                _ | c >= ord_ '0' && c <= ord_ '9' -> c - ord_ '0'
                  | c >= ord_ 'a' && c <= ord_ 'f' -> 10 + c - ord_ 'a'
                  | c >= ord_ 'A' && c <= ord_ 'F' -> 10 + c - ord_ 'A'
                  | otherwise -> error $ "invalid hex character: " ++ show (chr $ fromIntegral c)
    where
        ord_ :: Char -> Word8
        ord_ = fromIntegral . ord

token :: String -> Parser t -> Parser t
token prefix p = string (C8.pack (prefix ++ ":")) *> p <* blank

ip :: Parser IP
ip = mkIP <$> decimal <* dot <*> decimal <* dot <*> decimal <* dot <*> decimal
    where
        dot = word8 46

i2h :: IP -> HostAddress
i2h (IPv4 ip) = flipbytes $ fromIntegral ip

blank = A.takeWhile1 (inClass "\t ")

portSpec :: Parser [Word8]
portSpec = concat <$> sepBy1 (portRange <|> port) (char ',')
    where
        portRange = (\a z -> [a..z]) <$> decimal <* char '-' <*> decimal
        port = (:[]) <$> decimal

ipSpec :: Parser [IP]
ipSpec = (\(IPv4 a) (IPv4 z) -> map IPv4 [a..z]) <$> ip <* dash <*> ip
    where
        dash = word8 45

mkLeaseDlink :: Maybe Mac -> Maybe HostAddress -> Maybe ByteString -> IP -> IP -> Int -> Word8 -> Word8 -> IP -> DhcpLease
mkLeaseDlink dl_mac dl_relay dl_remote dl_router dl_dns vlan dl_mask port dl_client = DhcpLease {..}
    where
        dl_circuit :: Maybe ByteString
        dl_circuit = Just $ B.pack [0, 4, vl, an, 0, port]
        vl = fromIntegral $ vlan `div` 256
        an = fromIntegral $ vlan `mod` 256



mkLeaseEdge :: Maybe Mac -> IP -> Maybe ByteString -> IP -> Int -> Word8 -> Word8 -> IP -> DhcpLease
mkLeaseEdge dl_mac dl_router dl_remote dl_dns vlan dl_mask port dl_client = DhcpLease{..}
    where
        dl_relay :: Maybe HostAddress
        dl_relay = Nothing
        dl_circuit :: Maybe ByteString
        dl_circuit = Just $ B.pack [0, 4, vl, an, 1, port]
        vl = fromIntegral $ vlan `div` 256
        an = fromIntegral $ vlan `mod` 256


mkLeaseRaw :: Maybe Mac -> Maybe ByteString -> Maybe ByteString -> IP -> IP -> Word8 -> IP -> DhcpLease
mkLeaseRaw dl_mac dl_circuit dl_remote dl_router dl_dns dl_mask dl_client = DhcpLease {..}
    where
        dl_relay = Nothing


flipbytes :: HostAddress -> HostAddress
flipbytes ip = o1 .|. o2 .|. o3 .|. o4
    where
        o1 = (ip .&. 0xFF000000) `shiftR` 24
        o2 = (ip .&. 0x00FF0000) `shiftR` 8
        o3 = (ip .&. 0x0000FF00) `shiftL` 8
        o4 = (ip .&. 0x000000FF) `shiftL` 24


-- 1. Тип Circuit ID
-- 2. Длина
-- 3. VLAN : VLAN ID DHCP-запроса клиента
-- 4. Module : Для автономного коммутатора, поле Module всегда 0; для стекируемого коммутатора, Module = Unit ID.
-- 5. Port : Порт коммутатора, с которого получен DHCP-запрос (начинается с 1) port
-- [0x00] [0x04] [0xVL] [0xAN] [MODL] [PORT]
--
--
-- 0 192.168.1.12     1  10.10.0.1 1-24 10.10.0.2-10.10.1.25
-- ^ circuit id type  ^ vlan  ^ router  ^ ip range
--   ^ relay agent ip    ^ port range

-- edge
