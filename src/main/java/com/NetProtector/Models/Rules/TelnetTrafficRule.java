package com.NetProtector.Models.Rules;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

/**
 * Rule to detect Telnet traffic (unencrypted login).
 * Telnet is insecure and its use should be monitored.
 */
public class TelnetTrafficRule implements Rule {

    private static final TcpPort TELNET_PORT = TcpPort.TELNET; // Port 23

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        TcpPacket tcpPacket = p.get(TcpPacket.class);
        if (tcpPacket != null) {
            // Check if either source or destination port is Telnet port
            if (tcpPacket.getHeader().getSrcPort().equals(TELNET_PORT) ||
                    tcpPacket.getHeader().getDstPort().equals(TELNET_PORT)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String getAlertName() {
        return "Telnet Traffic Detected";
    }

    @Override
    public String getAlertDescription() {
        return "Unencrypted Telnet traffic detected on port 23. Telnet is insecure and poses a security risk.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.MEDIUM;
    }

    @Override
    public String getName() {
        return "Telnet Traffic";
    }
}