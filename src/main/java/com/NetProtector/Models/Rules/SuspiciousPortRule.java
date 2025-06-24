package com.NetProtector.Models.Rules;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * Rule to detect traffic to or from a known suspicious port (e.g., associated with malware).
 * For demonstration, let's say port 6667 (often used by IRC bots/malware) is suspicious.
 */
public class SuspiciousPortRule implements Rule {

    private static final TcpPort SUSPICIOUS_TCP_PORT = new TcpPort((short) 6667, "IRC_Malware_TCP");
    private static final UdpPort SUSPICIOUS_UDP_PORT = new UdpPort((short) 6667, "IRC_Malware_UDP");


    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        TcpPacket tcpPacket = p.get(TcpPacket.class);
        if (tcpPacket != null) {
            TcpPort srcPort = tcpPacket.getHeader().getSrcPort();
            TcpPort dstPort = tcpPacket.getHeader().getDstPort();
            if (srcPort.equals(SUSPICIOUS_TCP_PORT) || dstPort.equals(SUSPICIOUS_TCP_PORT)) {
                return true;
            }
        }

        UdpPacket udpPacket = p.get(UdpPacket.class);
        if (udpPacket != null) {
            UdpPort srcPort = udpPacket.getHeader().getSrcPort();
            UdpPort dstPort = udpPacket.getHeader().getDstPort();
            if (srcPort.equals(SUSPICIOUS_UDP_PORT) || dstPort.equals(SUSPICIOUS_UDP_PORT)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String getAlertName() {
        return "Suspicious Port Activity";
    }

    @Override
    public String getAlertDescription() {
        return "Network traffic detected to or from a port commonly associated with malware or suspicious activity (e.g., port 6667).";
    }

    @Override
    public Severity getSeverity() {
        return Severity.MEDIUM;
    }

    @Override
    public String getName() {
        return "Suspicous Port";
    }
}