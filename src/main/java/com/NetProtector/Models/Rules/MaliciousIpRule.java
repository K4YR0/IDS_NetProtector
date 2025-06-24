package com.NetProtector.Models.Rules;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.util.HashSet;
import java.util.Set;

/**
 * Rule to detect traffic from known malicious IP addresses or suspicious geographical locations.
 * This is a LOW severity rule for basic threat intelligence monitoring.
 */
public class MaliciousIpRule implements Rule {

    // Sample known malicious IP ranges and specific IPs
    private static final Set<String> KNOWN_MALICIOUS_IPS = new HashSet<>();
    private static final Set<String> SUSPICIOUS_IP_RANGES = new HashSet<>();
    
    static {
        // Add some example malicious IPs (in real implementation, this would be from threat intel feeds)
        KNOWN_MALICIOUS_IPS.add("192.168.100.100"); // Example malicious IP
        KNOWN_MALICIOUS_IPS.add("10.0.0.99");       // Example malicious IP
        KNOWN_MALICIOUS_IPS.add("172.16.1.100");    // Example malicious IP
        
        // Add suspicious IP ranges (commonly used by botnets, tor exit nodes, etc.)
        SUSPICIOUS_IP_RANGES.add("203.0.113");      // TEST-NET-3 (example)
        SUSPICIOUS_IP_RANGES.add("198.51.100");     // TEST-NET-2 (example)
        SUSPICIOUS_IP_RANGES.add("192.0.2");        // TEST-NET-1 (example)
    }

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        IpV4Packet ipPacket = p.get(IpV4Packet.class);
        if (ipPacket != null) {
            String srcAddr = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstAddr = ipPacket.getHeader().getDstAddr().getHostAddress();
            
            // Check source IP against known malicious IPs
            if (KNOWN_MALICIOUS_IPS.contains(srcAddr)) {
                return true;
            }
            
            // Check destination IP against known malicious IPs
            if (KNOWN_MALICIOUS_IPS.contains(dstAddr)) {
                return true;
            }
            
            // Check against suspicious IP ranges
            for (String range : SUSPICIOUS_IP_RANGES) {
                if (srcAddr.startsWith(range) || dstAddr.startsWith(range)) {
                    return true;
                }
            }
            
            // Additional checks for suspicious patterns
            if (isSuspiciousIpPattern(srcAddr) || isSuspiciousIpPattern(dstAddr)) {
                return true;
            }
        }
        
        return false;
    }

    private boolean isSuspiciousIpPattern(String ipAddress) {
        // Check for private IPs communicating externally (potential data exfiltration)
        if (isPrivateIp(ipAddress)) {
            return false; // Private IPs are not inherently suspicious
        }
        
        // Check for reserved or special-use IP addresses that shouldn't appear in normal traffic
        if (ipAddress.startsWith("0.") ||           // "This" network
            ipAddress.startsWith("127.") ||         // Loopback
            ipAddress.startsWith("169.254.") ||     // Link-local
            ipAddress.startsWith("224.") ||         // Multicast
            ipAddress.startsWith("240.")) {         // Reserved
            return true;
        }
        
        // Check for sequential IP patterns (might indicate scanning)
        String[] octets = ipAddress.split("\\.");
        if (octets.length == 4) {
            try {
                int lastOctet = Integer.parseInt(octets[3]);
                // Sequential IPs ending in 1, 2, 3... might be from scanning
                if (lastOctet < 10) {
                    return true;
                }
            } catch (NumberFormatException e) {
                // Invalid IP format is also suspicious
                return true;
            }
        }
        
        return false;
    }

    private boolean isPrivateIp(String ipAddress) {
        return ipAddress.startsWith("192.168.") ||
               ipAddress.startsWith("10.") ||
               (ipAddress.startsWith("172.") && 
                ipAddress.split("\\.").length > 1 &&
                Integer.parseInt(ipAddress.split("\\.")[1]) >= 16 &&
                Integer.parseInt(ipAddress.split("\\.")[1]) <= 31);
    }

    @Override
    public String getAlertName() {
        return "Malicious IP Communication";
    }

    @Override
    public String getAlertDescription() {
        return "Network communication detected with an IP address known to be associated with malicious activities or from a suspicious geographical location.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.LOW;
    }

    @Override
    public String getName() {
        return "Malicious IP Detection";
    }
}
