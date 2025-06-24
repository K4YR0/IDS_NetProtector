package com.NetProtector.Models.Rules;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

/**
 * Rule to detect potential data exfiltration attempts by monitoring large outbound transfers.
 * This is a HIGH severity rule as data exfiltration can lead to significant data breaches.
 */
public class DataExfiltrationRule implements Rule {

    private static final int LARGE_TRANSFER_THRESHOLD = 10485760; // 10MB in bytes
    private static final int SUSPICIOUS_PACKET_SIZE = 1400; // Near MTU size packets

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        IpV4Packet ipPacket = p.get(IpV4Packet.class);
        TcpPacket tcpPacket = p.get(TcpPacket.class);
        
        if (ipPacket != null && tcpPacket != null) {
            // Check for large packet sizes (potential bulk data transfer)
            if (ipPacket.length() >= SUSPICIOUS_PACKET_SIZE) {
                
                // Check if this is outbound traffic from internal network
                String srcAddr = ipPacket.getHeader().getSrcAddr().getHostAddress();
                String dstAddr = ipPacket.getHeader().getDstAddr().getHostAddress();
                
                if (isInternalIp(srcAddr) && !isInternalIp(dstAddr)) {
                    // Outbound traffic from internal to external
                    
                    // Check for suspicious patterns in payload
                    if (tcpPacket.getPayload() != null) {
                        byte[] payload = tcpPacket.getPayload().getRawData();
                        if (payload != null && payload.length > 0) {
                            if (containsSuspiciousDataPatterns(payload)) {
                                return true;
                            }
                        }
                    }
                    
                    // Check for non-standard ports (potential covert channels)
                    int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
                    if (isSuspiciousPort(dstPort)) {
                        return true;
                    }
                    
                    // Large packets to external destinations are suspicious
                    if (ipPacket.length() > SUSPICIOUS_PACKET_SIZE * 2) {
                        return true;
                    }
                }
            }
            
            // Check for encrypted data patterns (potential encrypted exfiltration)
            if (tcpPacket.getPayload() != null) {
                byte[] payload = tcpPacket.getPayload().getRawData();
                if (payload != null && isLikelyEncrypted(payload)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private boolean isInternalIp(String ipAddress) {
        return ipAddress.startsWith("192.168.") ||
               ipAddress.startsWith("10.") ||
               (ipAddress.startsWith("172.") && 
                ipAddress.split("\\.").length > 1 &&
                Integer.parseInt(ipAddress.split("\\.")[1]) >= 16 &&
                Integer.parseInt(ipAddress.split("\\.")[1]) <= 31);
    }

    private boolean isSuspiciousPort(int port) {
        // Common legitimate ports that should not be used for large data transfers
        int[] commonPorts = {80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995};
        for (int commonPort : commonPorts) {
            if (port == commonPort) {
                return false; // These are normal
            }
        }
        
        // High ports might be suspicious for large transfers
        return port > 1024 && port < 65535;
    }

    private boolean containsSuspiciousDataPatterns(byte[] payload) {
        String payloadString = new String(payload);
        
        // Look for file headers that might indicate file exfiltration
        String[] fileHeaders = {
            "PK", // ZIP files
            "PDF", // PDF files
            "GIF", // GIF images
            "JFIF", // JPEG images
            "%PDF", // PDF files
            "<?xml", // XML files
            "{", // JSON files
            "BEGIN", // Certificate files
        };
        
        for (String header : fileHeaders) {
            if (payloadString.startsWith(header)) {
                return true;
            }
        }
        
        // Check for base64 encoded data (common in data exfiltration)
        if (isLikelyBase64(payloadString)) {
            return true;
        }
        
        return false;
    }

    private boolean isLikelyBase64(String data) {
        if (data.length() < 10) return false;
        
        // Base64 typically uses A-Z, a-z, 0-9, +, /, =
        int validChars = 0;
        for (char c : data.toCharArray()) {
            if (Character.isLetterOrDigit(c) || c == '+' || c == '/' || c == '=') {
                validChars++;
            }
        }
        
        // If more than 90% of characters are valid base64 characters
        return (double) validChars / data.length() > 0.9;
    }

    private boolean isLikelyEncrypted(byte[] data) {
        if (data.length < 100) return false;
        
        // Calculate entropy to detect encrypted/compressed data
        int[] frequency = new int[256];
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }
        
        double entropy = 0.0;
        for (int freq : frequency) {
            if (freq > 0) {
                double probability = (double) freq / data.length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }
        
        // High entropy suggests encrypted or compressed data
        return entropy > 7.5; // High entropy threshold
    }

    @Override
    public String getAlertName() {
        return "Potential Data Exfiltration";
    }

    @Override
    public String getAlertDescription() {
        return "Large outbound data transfer detected that may indicate data exfiltration. This could involve sensitive files being transmitted to external locations.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.HIGH;
    }

    @Override
    public String getName() {
        return "Data Exfiltration Detection";
    }
}
