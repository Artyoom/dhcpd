module Dhcp.Config ( getLeases 
                   , initLeases 
                   ) where

import Control.Applicative
import Control.Concurrent.STM
import Control.Concurrent.STM.TVar
import Data.Attoparsec as A
import Data.Attoparsec.Char8 (decimal, isSpace_w8, space, char)
import Data.Bits
import Data.ByteString (ByteString)
import Dhcp.Types
import Data.Word
import Network.Socket
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Data.Map (Map)
import qualified Data.Map as M

type LeaseDB = [DhcpLease]

getLeases :: IO (TVar (Map ByteString DhcpLease))
getLeases = undefined
{-    newTVarIO
-}

initLeases :: IO [DhcpLease]
initLeases = do
        file <- B.readFile "dhcp.conf"
        case (feed (parse leasesLines file) B.empty) of
            Partial _ -> error "Error in attoparsec"
            Done rest result -> if (B.null rest) then return result else (error $ "unparsed tail: " ++ show rest)
            Fail _ _ msg -> error $ "Failed to read dhcp.conf: " ++ msg

leasesLines :: Parser [DhcpLease]
leasesLines = concat <$> A.many (leases <* word8 10)

leases :: Parser [DhcpLease]
leases = lease_dlink

lease_dlink :: Parser [DhcpLease]
lease_dlink = do
    string (C8.pack "dlink") <* blank
    relay   <-  token "ip"     (i2h <$> ip)
    vlan    <-  token "vlan"   decimal
    router  <-  token "gw"     ip
    dns     <-  token "dns"    ip
    ports   <-  token "ports"  portSpec
    base    <-  token_l "base" ip
    mask    <-  char '/' *> decimal 
    return $ zipWith (mkLeaseDlink relay router dns vlan mask) ports (zipWith addToIP (map pred ports) (repeat base))

token :: String -> Parser t -> Parser t
token prefix p = string (C8.pack (prefix ++ ":")) *> p <* blank

token_l :: String -> Parser t -> Parser t
token_l prefix p = string (C8.pack (prefix ++ ":")) *> p

ip :: Parser IP
ip = mkIP <$> decimal <* dot <*> decimal <* dot <*> decimal <* dot <*> decimal
    where
        dot = word8 46

i2h :: IP -> HostAddress
i2h (IPv4 ip) = flipbytes $ fromIntegral ip

blank = A.takeWhile1 isSpace_w8

portSpec :: Parser [Word8]
portSpec = concat <$> sepBy1 (portRange <|> port) (char ',')
    where
        portRange = (\a z -> [a..z]) <$> decimal <* char '-' <*> decimal
        port = (:[]) <$> decimal

ipSpec :: Parser [IP]
ipSpec = (\(IPv4 a) (IPv4 z) -> map IPv4 [a..z]) <$> ip <* dash <*> ip
    where
        dash = word8 45

mkLeaseDlink :: HostAddress -> IP -> IP -> Int -> Word8 -> Word8 -> IP -> DhcpLease
mkLeaseDlink    relay         router dns  vlan    mask     port  client = DhcpLease
        { dl_relay   = relay
        , dl_router  = router
        , dl_dns     = dns
        , dl_circuit = circuit
        , dl_client  = client
        , dl_mask    = mask
        }
    where
        circuit :: ByteString
        circuit = B.pack [0, 4, vl, an, 0, port]
        vl = fromIntegral $ vlan `div` 256
        an = fromIntegral $ vlan `mod` 256



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
