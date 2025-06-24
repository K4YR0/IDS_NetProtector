package com.NetProtector.Models.Rules;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rule to detect potential DDoS attacks by monitoring traffic patterns.
 * Detects high volume of packets from single sources or to single destinations.
 * This is a HIGH severity rule as DDoS attacks can severely impact network performance.
 */
public class DdosDetectionRule implements Rule {

    private static final int PACKET_THRESHOLD = 100; // Packets per source in monitoring window
    private static final long TIME_WINDOW = 30000; // 30 seconds in milliseconds
    
    private final Map<String, PacketCounter> sourceCounters = new ConcurrentHashMap<>();
    private final Map<String, PacketCounter> destinationCounters = new ConcurrentHashMap<>();
    
    private static class PacketCounter {
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
            return count.incrementAndGet() > PACKET_THRESHOLD;
        }
    }

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        IpV4Packet ipPacket = p.get(IpV4Packet.class);
        if (ipPacket != null) {
            String srcAddr = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstAddr = ipPacket.getHeader().getDstAddr().getHostAddress();
            
            // Check for high volume from single source
            sourceCounters.putIfAbsent(srcAddr, new PacketCounter());
            if (sourceCounters.get(srcAddr).increment()) {
                return true;
            }
            
            // Check for high volume to single destination (potential target)
            destinationCounters.putIfAbsent(dstAddr, new PacketCounter());
            if (destinationCounters.get(dstAddr).increment()) {
                return true;
            }
        }
        
        return false;
    }

    @Override
    public String getAlertName() {
        return "Potential DDoS Attack Detected";
    }

    @Override
    public String getAlertDescription() {
        return "High volume of network traffic detected from a single source or to a single destination, which may indicate a Distributed Denial of Service (DDoS) attack attempt.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.HIGH;
    }

    @Override
    public String getName() {
        return "DDoS Detection";
    }
}
