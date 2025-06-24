package com.NetProtector.Models.Rules;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rule to detect ICMP flood attacks, which can be used for DoS attacks.
 * This is a MEDIUM severity rule as ICMP floods can degrade network performance.
 */
public class IcmpFloodRule implements Rule {

    private static final int ICMP_THRESHOLD = 50; // ICMP packets per source in time window
    private static final long TIME_WINDOW = 10000; // 10 seconds in milliseconds
    
    private final ConcurrentHashMap<String, IcmpCounter> icmpCounters = new ConcurrentHashMap<>();
    
    private static class IcmpCounter {
        private final AtomicInteger count = new AtomicInteger(0);
        private volatile long firstPacketTime = System.currentTimeMillis();
        
        public boolean increment() {
            long currentTime = System.currentTimeMillis();
            if (currentTime - firstPacketTime > TIME_WINDOW) {
                // Reset counter for new time window
                count.set(1);
                firstPacketTime = currentTime;
                return false;
            }
            return count.incrementAndGet() > ICMP_THRESHOLD;
        }
    }

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        IcmpV4CommonPacket icmpPacket = p.get(IcmpV4CommonPacket.class);
        if (icmpPacket != null) {
            IpV4Packet ipPacket = p.get(IpV4Packet.class);
            if (ipPacket != null) {
                String srcAddr = ipPacket.getHeader().getSrcAddr().getHostAddress();
                
                // Track ICMP packets per source
                icmpCounters.putIfAbsent(srcAddr, new IcmpCounter());
                if (icmpCounters.get(srcAddr).increment()) {
                    return true;
                }
                
                // Additional checks for suspicious ICMP patterns
                if (isSuspiciousIcmpPattern(icmpPacket)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private boolean isSuspiciousIcmpPattern(IcmpV4CommonPacket icmpPacket) {
        // Check for large ICMP packets (potential for amplification attacks)
        if (icmpPacket.length() > 1024) { // Unusually large ICMP packet
            return true;
        }
        
        // Check ICMP type for potentially malicious uses
        byte icmpType = icmpPacket.getHeader().getType().value();
        
        // Suspicious ICMP types
        switch (icmpType) {
            case 13: // Timestamp request
            case 14: // Timestamp reply
            case 15: // Information request
            case 16: // Information reply
            case 17: // Address mask request
            case 18: // Address mask reply
                return true; // These are often used in reconnaissance
        }
        
        return false;
    }

    @Override
    public String getAlertName() {
        return "ICMP Flood Attack";
    }

    @Override
    public String getAlertDescription() {
        return "High volume of ICMP packets detected from a single source, which may indicate an ICMP flood attack or network reconnaissance activity.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.MEDIUM;
    }

    @Override
    public String getName() {
        return "ICMP Flood Detection";
    }
}
