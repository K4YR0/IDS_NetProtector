package com.NetProtector.Models;

import java.util.concurrent.BlockingQueue;


import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
/**
 * @author Stika
 **/
public class PacketCaptureModel {

    private BlockingQueue<Packet> PacketQueue;
    private PcapHandle handle;


    public PacketCaptureModel(BlockingQueue<Packet> packets){
        PacketQueue = packets;
    }

    public void startCapture(PcapNetworkInterface networkInterface, String bpfFilter) throws PcapNativeException, NotOpenException {
        int snapLen = 65536;
        int timeout = 10;

        handle = networkInterface.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
        handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);

       System.out.println("Starting packet capture...");
        new Thread(() -> {
            try {
                handle.loop(-1, (PacketListener) packet -> {
                    try {
                        PacketQueue.put(packet);
                        System.out.println("Packet added to queue: ");
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        System.out.println("Failed to add packet to queue" + e);
                    }
                });
            } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                System.out.println( "Error during packet capture" + e);
            }
        }).start();
    }
}
