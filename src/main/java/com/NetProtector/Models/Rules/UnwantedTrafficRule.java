package com.NetProtector.Models.Rules;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Rule to detect potentially unwanted network behavior such as P2P traffic,
 * gaming protocols, or non-business applications during work hours.
 * This is a LOW severity rule for policy enforcement and bandwidth management.
 */
public class UnwantedTrafficRule implements Rule {

    // Common P2P and gaming ports
    private static final Set<Integer> P2P_PORTS = new HashSet<>(Arrays.asList(
        6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, // BitTorrent
        4662, 4672, // eMule
        1214, // Kazaa
        6346, 6347, // Gnutella
        412, 413    // DC++
    ));

    private static final Set<Integer> GAMING_PORTS = new HashSet<>(Arrays.asList(
        27015, 27016, 27017, 27018, 27019, // Steam
        3724, // World of Warcraft
        1119, // Battle.net
        6112, 6113, 6114, 6115, 6116, 6117, 6118, 6119, // Battle.net games
        7777, 7778, 7779, // Unreal Tournament
        28960 // Call of Duty
    ));

    private static final Set<Integer> STREAMING_PORTS = new HashSet<>(Arrays.asList(
        1935, // RTMP (Flash streaming)
        554,  // RTSP
        8080, // Alternative HTTP (often used for streaming)
        8554  // Alternative RTSP
    ));

    private static final String[] UNWANTED_PROTOCOLS = {
        "BITTORRENT", "TORRENT", "PEER", "LIMEWIRE", "KAZAA",
        "STEAM", "GAMING", "NETFLIX", "YOUTUBE", "TWITCH"
    };

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        TcpPacket tcpPacket = p.get(TcpPacket.class);
        UdpPacket udpPacket = p.get(UdpPacket.class);
        
        if (tcpPacket != null) {
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            
            // Check for P2P traffic
            if (P2P_PORTS.contains(srcPort) || P2P_PORTS.contains(dstPort)) {
                return true;
            }
            
            // Check for gaming traffic
            if (GAMING_PORTS.contains(srcPort) || GAMING_PORTS.contains(dstPort)) {
                return true;
            }
            
            // Check for streaming traffic
            if (STREAMING_PORTS.contains(srcPort) || STREAMING_PORTS.contains(dstPort)) {
                return true;
            }
            
            // Analyze payload for protocol signatures
            if (tcpPacket.getPayload() != null) {
                byte[] payload = tcpPacket.getPayload().getRawData();
                if (payload != null && containsUnwantedProtocol(payload)) {
                    return true;
                }
            }
        }
        
        if (udpPacket != null) {
            int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
            
            // Check for P2P traffic over UDP
            if (P2P_PORTS.contains(srcPort) || P2P_PORTS.contains(dstPort)) {
                return true;
            }
            
            // Check for gaming traffic over UDP
            if (GAMING_PORTS.contains(srcPort) || GAMING_PORTS.contains(dstPort)) {
                return true;
            }
            
            // Analyze payload for protocol signatures
            if (udpPacket.getPayload() != null) {
                byte[] payload = udpPacket.getPayload().getRawData();
                if (payload != null && containsUnwantedProtocol(payload)) {
                    return true;
                }
            }
        }
        
        // Check for excessive bandwidth usage patterns
        if (isHighBandwidthPattern(p)) {
            return true;
        }
        
        return false;
    }

    private boolean containsUnwantedProtocol(byte[] payload) {
        String payloadString = new String(payload).toUpperCase();
        
        for (String protocol : UNWANTED_PROTOCOLS) {
            if (payloadString.contains(protocol)) {
                return true;
            }
        }
        
        // Check for BitTorrent protocol signatures
        if (payloadString.contains("ANNOUNCE") && payloadString.contains("PEER")) {
            return true;
        }
        
        // Check for common P2P handshakes
        if (payloadString.contains("HANDSHAKE") || payloadString.contains("PROTOCOL")) {
            return true;
        }
        
        return false;
    }

    private boolean isHighBandwidthPattern(Packet p) {
        IpV4Packet ipPacket = p.get(IpV4Packet.class);
        if (ipPacket != null) {
            // Large packets might indicate file sharing or streaming
            if (ipPacket.length() > 1400) { // Near MTU size
                return true;
            }
        }
        
        return false;
    }

    @Override
    public String getAlertName() {
        return "Unwanted Network Traffic";
    }

    @Override
    public String getAlertDescription() {
        return "Network traffic detected that may violate corporate policy, including P2P file sharing, gaming, or streaming applications that could impact business bandwidth and productivity.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.LOW;
    }

    @Override
    public String getName() {
        return "Unwanted Traffic Detection";
    }
}
