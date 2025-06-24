package com.NetProtector.Models.Rules;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

/**
 * Rule to detect potential SQL injection attempts by analyzing TCP payload for SQL injection patterns.
 * This is a CRITICAL severity rule as SQL injection can lead to complete database compromise.
 */
public class SqlInjectionRule implements Rule {

    private static final String[] SQL_INJECTION_PATTERNS = {
        "' OR '1'='1",
        "' OR 1=1",
        "'; DROP TABLE",
        "'; DELETE FROM",
        "UNION SELECT",
        "' UNION SELECT",
        "1' AND 1=1",
        "admin'--",
        "' OR 'a'='a",
        "1' OR '1'='1'--",
        "') OR ('1'='1",
        "' WAITFOR DELAY",
        "'; EXEC ",
        "' AND SUBSTRING(",
        "'; INSERT INTO"
    };

    @Override
    public boolean verify(Packet p) {
        if (p == null) {
            return false;
        }

        TcpPacket tcpPacket = p.get(TcpPacket.class);
        if (tcpPacket != null && tcpPacket.getPayload() != null) {
            byte[] payload = tcpPacket.getPayload().getRawData();
            if (payload != null && payload.length > 0) {
                String payloadString = new String(payload).toUpperCase();
                
                // Check for SQL injection patterns
                for (String pattern : SQL_INJECTION_PATTERNS) {
                    if (payloadString.contains(pattern.toUpperCase())) {
                        return true;
                    }
                }
                
                // Additional heuristic checks
                if (containsSqlInjectionHeuristics(payloadString)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private boolean containsSqlInjectionHeuristics(String payload) {
        // Check for multiple SQL keywords in close proximity
        String[] sqlKeywords = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "UNION"};
        int keywordCount = 0;
        
        for (String keyword : sqlKeywords) {
            if (payload.contains(keyword)) {
                keywordCount++;
            }
        }
        
        // If multiple SQL keywords and common injection characters
        if (keywordCount >= 2 && (payload.contains("'") || payload.contains("--") || payload.contains("/*"))) {
            return true;
        }
        
        return false;
    }

    @Override
    public String getAlertName() {
        return "SQL Injection Attack Detected";
    }

    @Override
    public String getAlertDescription() {
        return "Potential SQL injection attempt detected in network traffic. SQL injection attacks can compromise database security and lead to unauthorized data access or manipulation.";
    }

    @Override
    public Severity getSeverity() {
        return Severity.CRITICAL;
    }

    @Override
    public String getName() {
        return "SQL Injection Detection";
    }
}
