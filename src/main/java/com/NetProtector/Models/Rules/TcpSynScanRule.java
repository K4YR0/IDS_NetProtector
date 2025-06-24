package com.NetProtector.Models.Rules;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Rule to detect a potential TCP SYN scan attempt on common ports.
 * A SYN scan is identified by a TCP packet with only the SYN flag set.
 * This rule checks for SYN packets to a list of common sensitive ports.
 */
public class TcpSynScanRule implements Rule {

    private static final Set<TcpPort> COMMON_SENSITIVE_PORTS = new HashSet<>(Arrays.asList(
            TcpPort.FTP_DATA, TcpPort.FTP, TcpPort.SSH, TcpPort.TELNET,
            TcpPort.SMTP, TcpPort.DOMAIN, TcpPort.HTTP, TcpPort.POP3,
            TcpPort.SFTP, TcpPort.IPCD, TcpPort.HTTPS, TcpPort.IMAPS, new TcpPort((short)8080, "HTTP_ALT") // Common HTTP alternative
    ));

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        TcpPacket tcpPacket = p.get(TcpPacket.class);
        if (tcpPacket != null) {
            // Check if only the SYN flag is set and ACK is not set
            if (tcpPacket.getHeader().getSyn() &&
                    !tcpPacket.getHeader().getAck() &&
                    !tcpPacket.getHeader().getRst() &&
                    !tcpPacket.getHeader().getFin() &&
                    !tcpPacket.getHeader().getPsh() &&
                    !tcpPacket.getHeader().getUrg()) {
                // Check if the destination port is one of the common sensitive ports
                return COMMON_SENSITIVE_PORTS.contains(tcpPacket.getHeader().getDstPort());
            }
        }
        return false;
    }

    @Override
    public String getAlertName() {
        return "Potential TCP SYN Scan";
    }

    @Override
    public String getAlertDescription() {
        return "A TCP packet with only the SYN flag set was detected targeting a common sensitive port. This could indicate a port scanning attempt.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.MEDIUM;
    }

    @Override
    public String getName() {
        return "Tcp Syn Scan";
    }
}