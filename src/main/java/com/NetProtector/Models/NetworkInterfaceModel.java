package com.NetProtector.Models;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

/**
 * @author Stika
 **/
public class NetworkInterfaceModel {


    public static List<PcapNetworkInterface> listInterfaces() throws PcapNativeException {
        return Pcaps.findAllDevs();
    }

    public static PcapNetworkInterface getInterfaceByIndex(int index) throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = listInterfaces();
        if (index < 0 || index >= interfaces.size()) {
            throw new IllegalArgumentException("Invalid interface index");
        }
        return interfaces.get(index);
    }
}
