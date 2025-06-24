package com.NetProtector.Models.Rules;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Type;

/**
 * Rule to detect ICMP Ping (Echo Request).
 * While not always malicious, frequent pings can be part of reconnaissance.
 */
public class PingDetectRule implements Rule {

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        // Check if it's an IPv4 packet first, as ICMPv4 is specific to IPv4
        IpV4Packet ipV4Packet = p.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            IcmpV4CommonPacket icmpPacket = p.get(IcmpV4CommonPacket.class);
            if (icmpPacket != null) {
                // Check if it's an Echo Request (Type 8)
                System.out.println("⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️");

                return icmpPacket.getHeader().getType().equals(IcmpV4Type.ECHO);
            }
        }
        return false;
    }

    @Override
    public String getAlertName() {
        return "ICMP Echo Request (Ping) Detected";
    }

    @Override
    public String getAlertDescription() {
        return "An ICMP Echo Request (Ping) packet was detected. This is often used for network reconnaissance.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.LOW;
    }

    @Override
    public String getName() {
        return "Ping Detect";
    }
}