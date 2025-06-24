package com.NetProtector.Models.Rules;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.nio.charset.StandardCharsets;

/**
 * Rule to detect a specific string in TCP packet payload.
 * This could be used for very basic signature-based detection.
 * Example: Detecting the string "nc -l -p" which might indicate a netcat listener setup.
 * CAUTION: Naive payload string matching can lead to many false positives and performance issues.
 */
public class SimplePayloadStringRule implements Rule {

    //  Example: "nc -l -p" or "powershell" or a known exploit string
    private static final String MALICIOUS_SIGNATURE = "nc -l -p";

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        TcpPacket tcpPacket = p.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getPayload() != null) {
            byte[] payloadBytes = tcpPacket.getPayload().getRawData();
            String payloadString = new String(payloadBytes, StandardCharsets.UTF_8); // Or another appropriate charset

            // Simple string containment check. For real-world use, more robust pattern matching (e.g., regex)
            // and consideration for obfuscation would be needed.
            if (payloadString.toLowerCase().contains(MALICIOUS_SIGNATURE.toLowerCase())) {
                System.out.println("⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️");

                return true;
            }
        }
        return false;
    }

    @Override
    public String getAlertName() {
        return "Potential Malicious Payload Detected";
    }

    @Override
    public String getAlertDescription() {
        return "A TCP packet payload contains a string ('" + MALICIOUS_SIGNATURE + "') that could indicate malicious activity.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.HIGH;
    }

    @Override
    public String getName() {
        return "Suspicious Payload";
    }
}