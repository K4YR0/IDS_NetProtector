package com.NetProtector.Models.Rules;

import org.pcap4j.packet.Packet;

/**
 * @author Stika
 **/
public interface Rule {
    boolean verify(Packet p);
    String getAlertName();
    String getAlertDescription();
    Severity getSeverity(); // "LOW", "MEDIUM", "HIGH"

    String getName();
}
