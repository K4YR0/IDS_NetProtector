package com.NetProtector.Models.Rules;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Rule to detect potential brute force login attempts by monitoring failed authentication patterns.
 * This is a HIGH severity rule as brute force attacks can lead to unauthorized access.
 */
public class BruteForceDetectionRule implements Rule {

    private static final Set<TcpPort> AUTH_PORTS = new HashSet<>(Arrays.asList(
        TcpPort.SSH,     // SSH (22)
        TcpPort.TELNET,  // Telnet (23)
        TcpPort.FTP,     // FTP (21)
        TcpPort.HTTP,    // HTTP (80) - for web login
        TcpPort.HTTPS,   // HTTPS (443) - for web login
        new TcpPort((short)3389, "RDP"), // RDP
        new TcpPort((short)5985, "WinRM"), // WinRM
        new TcpPort((short)5986, "WinRM_HTTPS") // WinRM HTTPS
    ));

    private static final String[] BRUTE_FORCE_INDICATORS = {
        "Authentication failed",
        "Login failed",
        "Invalid username",
        "Invalid password",
        "Access denied",
        "401 Unauthorized",
        "403 Forbidden",
        "login incorrect",
        "authentication failure",
        "bad password",
        "failed login"
    };

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        TcpPacket tcpPacket = p.get(TcpPacket.class);
        if (tcpPacket != null) {
            TcpPort dstPort = tcpPacket.getHeader().getDstPort();
            TcpPort srcPort = tcpPacket.getHeader().getSrcPort();
            
            // Check if targeting authentication services
            if (AUTH_PORTS.contains(dstPort) || AUTH_PORTS.contains(srcPort)) {
                if (tcpPacket.getPayload() != null) {
                    byte[] payload = tcpPacket.getPayload().getRawData();
                    if (payload != null && payload.length > 0) {
                        String payloadString = new String(payload).toLowerCase();
                        
                        // Check for authentication failure indicators
                        for (String indicator : BRUTE_FORCE_INDICATORS) {
                            if (payloadString.contains(indicator.toLowerCase())) {
                                return true;
                            }
                        }
                        
                        // Additional checks for rapid connection attempts
                        if (isSuspiciousAuthPattern(tcpPacket, payloadString)) {
                            return true;
                        }
                    }
                }
                
                // Check for SYN flood to auth services (potential brute force prep)
                if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private boolean isSuspiciousAuthPattern(TcpPacket tcpPacket, String payload) {
        // Look for common brute force patterns
        if (payload.contains("user") && payload.contains("pass")) {
            return true;
        }
        
        // Check for automated tool signatures
        String[] toolSignatures = {
            "hydra", "medusa", "ncrack", "patator", "brutespray"
        };
        
        for (String signature : toolSignatures) {
            if (payload.contains(signature)) {
                return true;
            }
        }
        
        return false;
    }

    @Override
    public String getAlertName() {
        return "Brute Force Attack Detected";
    }

    @Override
    public String getAlertDescription() {
        return "Potential brute force authentication attack detected. Multiple failed login attempts or suspicious authentication patterns observed on common service ports.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.HIGH;
    }

    @Override
    public String getName() {
        return "Brute Force Detection";
    }
}
