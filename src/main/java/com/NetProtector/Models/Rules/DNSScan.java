package com.NetProtector.Models.Rules;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * @author Stika
 * Rule to detect DNS (Domain Name System) traffic.
 * DNS typically uses UDP port 53.
 */
public class DNSScan implements Rule { // Consider renaming to DNSTrafficDetectRule if not specifically for "scanning"

    private static final UdpPort DNS_PORT = UdpPort.DOMAIN; // Standard DNS port 53

    public DNSScan() {
    }

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        // DNS typically runs over UDP, so check for UdpPacket
        UdpPacket udpPacket = p.get(UdpPacket.class);

        if (udpPacket != null) {
            UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
            IpPacket ipPacket = p.get(IpPacket.class); // Get IP packet for source/destination IPs in description

            // Check if either source or destination port is the DNS port (53)
            if (udpHeader.getDstPort().equals(DNS_PORT) || udpHeader.getSrcPort().equals(DNS_PORT)) {


                if (ipPacket != null && ipPacket.getHeader() != null) {
                    System.out.println("⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️");
                    System.out.println("⚠️ DNS packet detected: " + ipPacket.getHeader().getSrcAddr() +
                            ":" + udpHeader.getSrcPort().valueAsInt() +
                            " -> " + ipPacket.getHeader().getDstAddr() +
                            ":" + udpHeader.getDstPort().valueAsInt());
                } else {
                    System.out.println("⚠️ DNS packet detected: Port " +
                            udpHeader.getSrcPort().valueAsInt() +
                            " to Port " + udpHeader.getDstPort().valueAsInt());
                }


                return true;
            }
        }
        return false;
    }

    @Override
    public String getAlertName() {
        return "DNS Traffic Detected"; // Corrected Name
    }

    @Override
    public String getAlertDescription() {
        // Provide more context if IpPacket is available, otherwise a generic message.
        // Note: Accessing packet details here might be redundant if the main engine already does it.
        // Keeping it simple for this example:
        return "A UDP packet using port 53 (DNS) was observed. This is typical for DNS queries or responses."; // Corrected Description
    }

    @Override
    public Severity getSeverity() {
        // Detecting general DNS traffic is usually low severity.
        // If this rule were to detect specific malicious DNS patterns (e.g., DNS tunneling, fast flux),
        // the severity might be higher.
        return Severity.LOW;
    }

    @Override
    public String getName() {
        return "DNS";
    }
}