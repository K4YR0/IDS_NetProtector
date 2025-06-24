package com.NetProtector.Models.Rules;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * Rule to detect DNS tunneling attempts, which can be used for data exfiltration
 * or command and control communication. This is a MEDIUM severity rule.
 */
public class DnsTunnelingRule implements Rule {

    private static final int SUSPICIOUS_QUERY_LENGTH = 50; // Unusually long DNS queries
    private static final int SUSPICIOUS_SUBDOMAIN_COUNT = 5; // Too many subdomains
    
    private static final String[] SUSPICIOUS_PATTERNS = {
        // Base64 encoding patterns (common in DNS tunneling)
        "AAAA", "BBBB", "CCCC", "DDDD",
        // Hex encoding patterns
        "0000", "1111", "FFFF",
        // Random-looking domains
        "XYZABC", "QWERTY"
    };

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        UdpPacket udpPacket = p.get(UdpPacket.class);
        if (udpPacket != null) {
            UdpPort dstPort = udpPacket.getHeader().getDstPort();
            UdpPort srcPort = udpPacket.getHeader().getSrcPort();
            
            // Check if it's DNS traffic (port 53)
            if (dstPort.equals(UdpPort.DOMAIN) || srcPort.equals(UdpPort.DOMAIN)) {
                if (udpPacket.getPayload() != null) {
                    byte[] payload = udpPacket.getPayload().getRawData();
                    if (payload != null && payload.length > 0) {
                        return analyzeDnsPayload(payload);
                    }
                }
            }
        }
        
        return false;
    }

    private boolean analyzeDnsPayload(byte[] payload) {
        try {
            String payloadString = new String(payload).toUpperCase();
            
            // Check for unusually long queries (potential data exfiltration)
            if (payloadString.length() > SUSPICIOUS_QUERY_LENGTH) {
                return true;
            }
            
            // Count subdomains (dots in domain name)
            int dotCount = 0;
            for (char c : payloadString.toCharArray()) {
                if (c == '.') {
                    dotCount++;
                }
            }
            
            if (dotCount > SUSPICIOUS_SUBDOMAIN_COUNT) {
                return true;
            }
            
            // Check for suspicious encoding patterns
            for (String pattern : SUSPICIOUS_PATTERNS) {
                if (payloadString.contains(pattern)) {
                    return true;
                }
            }
            
            // Check for high entropy (random-looking data)
            if (calculateEntropy(payloadString) > 4.5) { // High entropy threshold
                return true;
            }
            
            // Check for non-standard DNS query patterns
            if (containsSuspiciousDnsPattern(payloadString)) {
                return true;
            }
            
        } catch (Exception e) {
            // If we can't parse the payload, it might be suspicious
            return true;
        }
        
        return false;
    }

    private double calculateEntropy(String data) {
        if (data.isEmpty()) return 0;
        
        int[] frequency = new int[256];
        for (char c : data.toCharArray()) {
            frequency[c]++;
        }
        
        double entropy = 0.0;
        int length = data.length();
        
        for (int freq : frequency) {
            if (freq > 0) {
                double probability = (double) freq / length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }
        
        return entropy;
    }

    private boolean containsSuspiciousDnsPattern(String payload) {
        // Check for unusual character patterns that might indicate tunneling
        int digitCount = 0;
        int letterCount = 0;
        
        for (char c : payload.toCharArray()) {
            if (Character.isDigit(c)) {
                digitCount++;
            } else if (Character.isLetter(c)) {
                letterCount++;
            }
        }
        
        // If mostly digits or unusual digit/letter ratio
        if (digitCount > letterCount * 2) {
            return true;
        }
        
        return false;
    }

    @Override
    public String getAlertName() {
        return "DNS Tunneling Detected";
    }

    @Override
    public String getAlertDescription() {
        return "Potential DNS tunneling activity detected. DNS tunneling can be used for data exfiltration, command and control communication, or bypassing network restrictions.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.MEDIUM;
    }

    @Override
    public String getName() {
        return "DNS Tunneling Detection";
    }
}
