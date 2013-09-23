{-# LANGUAGE RecordWildCards #-}
module Main
where

import Control.Applicative
import Control.Exception
import Control.Monad.IO.Class
import Data.Bits
import Data.ByteString (ByteString)
import Data.Iteratee hiding (head, foldl, take, mapM_, length)
import Data.Maybe (isJust, fromJust, listToMaybe)
import Data.List (find)
import Dhcp.Config
import Dhcp.Decode
import Dhcp.Encode
import Dhcp.Types
import Network hiding (accept)
import Network.Socket hiding (Debug)
import System.Posix.Syslog
import qualified Data.ByteString as B
import qualified Network.Socket.ByteString as NB

enumUdp :: Int -> Enumerator [(ByteString, SockAddr)] IO (Maybe (ByteString, SockAddr)) -- {{{
enumUdp port i = bracket initSocket sClose (flip processData i)
    where
        initSocket :: IO Socket
        initSocket = do serveraddr <- head <$> getAddrInfo (Just (defaultHints {addrFlags = [AI_PASSIVE]})) Nothing (Just $ show port)
                        sock <- socket (addrFamily serveraddr) Datagram defaultProtocol
                        bindSocket sock (addrAddress serveraddr)
                        syslog Info $ "Listening for connects from " ++ show sock
                        return sock

        processData :: Socket -> Enumerator [(ByteString, SockAddr)] IO (Maybe (ByteString, SockAddr))
        processData sock iter = NB.recvFrom sock 4096 >>= 
                        flip enumChunk iter . Chunk . (:[]) >>= run >>=
                        \result -> case result of
                            (Just v) -> uncurry (NB.sendTo sock) v >> processData sock iter
                            Nothing  -> processData sock iter
-- }}}

dhcpIter :: [DhcpLease] -> Iteratee [(ByteString, SockAddr)] IO (Maybe (ByteString, SockAddr)) -- {{{
dhcpIter db = liftI go
    where
        go (Chunk [(msg, addr)]) = do
            let request = decodeRequest msg
                reply = request >>= makeDhcpReply db addr
                result = reply >>= \r -> return (encodeReply r, mkReplyAddr addr)
            liftIO $ mapM_ (uncurry syslog) (trace msg addr db request reply)
            idone result (Chunk [])
        
        go e = error $ "got EOF: " ++ show e
-- }}}

trace :: ByteString -> SockAddr -> [DhcpLease] -> Maybe DhcpRequest -> Maybe DhcpReply -> [(Priority, String)]
trace _ (SockAddrInet6 _ _ _ _) _ _ _ = [(Info, "I got request via ipv6 and do not know what to do with it, so request will probably fail")]
trace _ (SockAddrUnix _) _ _ _ = [(Info, "I got request via unix socket (dunno how) and do not know what to do with it, so request will probably fail")]
trace _ _ _ (Just (REQUEST h ip _))   (Just (ACK _ ip' _)) 
    | isJust ip = [(Info, "User REQUESTed for " ++ show (fromJust ip) ++ " and was given " ++ show ip' ++ via h)]
    | otherwise = [(Info, "User REQUESTed for ANY ip and was given " ++ show ip' ++ via h)]
trace _ _ _ (Just (REQUEST h (Just ip) _)) (Just (NAK _)) = [(Info, "User REQUESTed for " ++ show ip ++ " and got NAK. Dunno why. It was" ++ via h)]
trace _ _ _ (Just (DISCOVER h ip _)) (Just (OFFER _ ip' _))
    | isJust ip = [(Info, "User DISCOVERs for " ++ show (fromJust ip) ++ " and was offered " ++ show ip' ++ via h)]
    | otherwise = [(Info, "User DISCOVERs for ANY ip and was offered " ++ show ip' ++ via h)]
trace _ _ _ (Just r@(REQUEST h _ o)) Nothing
    | noOption82 o = [(Info, "User requested for something " ++ show r ++ ", and i could not answer him because he didn't had option82 tag" ++ via h)]
    | otherwise = [(Info, "User requested for something " ++ show r ++ ", and i could not answer him. And he had option82 tag" ++ via h)]
trace _ _ _ (Just r@(DISCOVER h _ o)) Nothing 
    | noOption82 o = [(Info, "User is trying to discover something" ++ show r ++ ", and i could not answer him because he didn't had option82 tag" ++ via h)]
    | otherwise = [(Info, "User is trying to discover something" ++ show r ++ ", and i could not answer him. And he had option82 tag" ++ via h)]
trace _ sock _ (Just msg) reply = [(Info, "I dunno what to do with all of those: " ++ show (sock,msg,reply))]
trace bs sock _ msg reply = [(Info, "I dunno what to do with all of those: " ++ show (B.unpack bs,sock,msg,reply))]



noOption82 :: [DhcpOption] -> Bool
noOption82 opts = Nothing == getOption82 opts

via :: BootpHeader -> String
via h = maybe "via broadcast" ((++) " via " . show) (h_gw h)


makeDhcpReply :: [DhcpLease] -> SockAddr -> DhcpRequest -> Maybe DhcpReply
makeDhcpReply db addr l = case l of
            (DISCOVER header _ options) -> lookupLease header db addr options >>= \lease -> return $ doDiscover header options lease
            (REQUEST header ip options) -> lookupLease header db addr options >>= \lease -> return $ doRequest header ip options lease
            (DECLINE _) -> Nothing
            RELEASE -> Nothing
            INFORM  -> Nothing

doDiscover :: BootpHeader -> [DhcpOption] -> DhcpLease -> DhcpReply
doDiscover header options lease = OFFER header (dl_client lease) (mkOptions options lease)

doRequest :: BootpHeader -> Maybe IP -> [DhcpOption] -> DhcpLease -> DhcpReply
doRequest header ip options lease = if ip == Nothing || ip == Just (dl_client lease)
                        then ACK header (dl_client lease) (mkOptions options lease)
                        else NAK header

mkOptions :: [DhcpOption] -> DhcpLease -> [DhcpOption]
mkOptions _ lease = subnetMask : router : dns : {- hostname : domainname : renew : rebind -} options' 
    where
        options' = [LeaseTime (3600 * 24), ServerID (mkIP 10 7 0 254)]
        subnetMask = SubnetMask . IPv4 . (\b -> complement . foldl (.|.) 0 . take (32 - b) . iterate (*2) $ 1) . fromIntegral . dl_mask $ lease
        router = RouterOption [dl_router $ lease]
        dns = DomainNameServer [dl_dns $ lease]

lookupLease :: BootpHeader -> [DhcpLease] -> SockAddr -> [DhcpOption] -> Maybe DhcpLease -- {{{
lookupLease _ _ (SockAddrInet6 _ _ _ _) _ = Nothing
lookupLease _ _ (SockAddrUnix _) _ = Nothing
lookupLease bootp leases (SockAddrInet _ host) opts = find (leaseMatches agentOpts) leases
    where
        agentOpts :: [AgentOption]
        agentOpts = concat [agent | RelayAgent agent <- opts]

        leaseMatches :: [AgentOption] -> DhcpLease -> Bool
        leaseMatches opts DhcpLease{..} = relayOk && circuitOk && remoteOk && macOk
            where
                relayOk  = maybe True (==host) dl_relay
                remoteOk = case dl_remote of
                                Nothing -> True
                                x@Just{} -> remote == dl_remote
                circuitOk = case dl_circuit of
                                Nothing -> True
                                x@Just{} -> circuit == dl_circuit

                macOk = case dl_mac of
                                Nothing -> True
                                Just mac -> mac == h_mac bootp

                remote  = listToMaybe [r | AgentRemoteID r <- opts]
                circuit = listToMaybe [c | AgentCircuitID c <- opts]

            {-
            relayOk = RelayAgent agentOpt
        dl_relay
        dl_circuit -}


getOption82   :: [DhcpOption] -> Maybe ByteString
getOption82 = listToMaybe  . getCircuitId . getRelayAgents
    where
        getRelayAgents opts = concat $ do { RelayAgent agent <- opts ; return agent }
        getCircuitId opts  = do { AgentCircuitID cir <- opts; return cir }
-- }}}

mkReplyAddr :: SockAddr -> SockAddr
mkReplyAddr (SockAddrInet _ host)   = SockAddrInet 67 host
mkReplyAddr (SockAddrInet6 _ f h s) = SockAddrInet6 67 f h s
mkReplyAddr (SockAddrUnix _)        = error "DHCP over unix sockets O_o?"

main :: IO ()
main = do
    leases <- initLeases 
    syslog Info $ "Got information about " ++ show (length leases) ++ "leases"
    enumUdp 67 (dhcpIter leases) >>= run >> return ()
