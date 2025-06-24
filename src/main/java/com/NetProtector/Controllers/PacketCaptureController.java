package com.NetProtector.Controllers;

import com.NetProtector.Models.NetworkInterfaceModel;
import com.NetProtector.Models.PacketCaptureModel;
import javafx.application.Platform;
import javafx.beans.property.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * @author Stika
 **/
public class PacketCaptureController {

    
    private NetworkInterfaceModel nifmodel;
    private PacketCaptureModel capturemodel;
      // Packet capture components
    private Thread captureThread;
    private final BlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<>();
    private final AtomicBoolean isCapturing = new AtomicBoolean(false);
    
    // JavaFX Properties for UI binding
    private final BooleanProperty capturing = new SimpleBooleanProperty(false);
    private final StringProperty status = new SimpleStringProperty("Ready");
    private final IntegerProperty packetCount = new SimpleIntegerProperty(0);
    private final StringProperty selectedInterface = new SimpleStringProperty("");
    private final StringProperty bpfFilter = new SimpleStringProperty("");
    
    // Observable lists for UI
    private final ObservableList<PcapNetworkInterface> availableInterfaces = FXCollections.observableArrayList();
    private final ObservableList<String> capturedPackets = FXCollections.observableArrayList();
    private final ObservableList<String> interfaceNames = FXCollections.observableArrayList();
    
    public PacketCaptureController() {
        this.nifmodel = new NetworkInterfaceModel();
        loadAvailableInterfaces();
    }
    
    /**
     * Load all available network interfaces
     */
    public void loadAvailableInterfaces() {
        try {
            List<PcapNetworkInterface> interfaces = NetworkInterfaceModel.listInterfaces();
            availableInterfaces.clear();
            interfaceNames.clear();
              if (interfaces == null || interfaces.isEmpty()) {
                System.out.println("No network interfaces detected");
                setStatus("No network interfaces found");
                return;
            }
            
            for (PcapNetworkInterface nif : interfaces) {
                availableInterfaces.add(nif);
                // Show only the interface name without description
                String displayName = nif.getDescription();
                interfaceNames.add(displayName);
            }
              setStatus("Found " + interfaces.size() + " network interfaces");
            System.out.println("Loaded " + interfaces.size() + " network interfaces");
            
        } catch (PcapNativeException e) {
            System.out.println("Failed to load network interfaces: " + e.getMessage());
            setStatus("Error loading interfaces: " + e.getMessage());
        }
    }
    
    /**
     * Start packet capture on selected interface
     */
    public void startCapture(int interfaceIndex, String filter) {
        if (isCapturing.get()) {
            System.out.println("Capture already in progress");
            return;
        }
        
        try {
            // Get the selected interface
            PcapNetworkInterface selectedNif = NetworkInterfaceModel.getInterfaceByIndex(interfaceIndex);
            
            // Initialize capture model
            this.capturemodel = new PacketCaptureModel(packetQueue);
            
            // Clear previous packets
            capturedPackets.clear();
            setPacketCount(0);
            
            // Set properties
            isCapturing.set(true);
            setCapturing(true);
            setSelectedInterface(selectedNif.getName());
            setBpfFilter(filter != null ? filter : "");
            setStatus("Starting capture...");
            
            // Start capture in background thread
            captureThread = new Thread(() -> {
                try {
                    capturemodel.startCapture(selectedNif, filter != null ? filter : "");
                    startPacketProcessing();                } catch (Exception e) {
                    System.out.println("Failed to start packet capture: " + e.getMessage());
                    Platform.runLater(() -> {
                        setStatus("Error starting capture: " + e.getMessage());
                        stopCapture();
                    });
                }
            });
            
            captureThread.setDaemon(true);
            captureThread.start();
              Platform.runLater(() -> setStatus("Capturing packets on " + selectedNif.getName()));
            System.out.println("Packet capture started on interface: " + selectedNif.getName());
            
        } catch (Exception e) {
            System.out.println("Failed to start packet capture: " + e.getMessage());
            setStatus("Error starting capture: " + e.getMessage());
            stopCapture();
        }
    }
    
    /**
     * Start processing packets from the queue
     */
    private void startPacketProcessing() {
        Thread processingThread = new Thread(() -> {
            while (isCapturing.get() && !Thread.currentThread().isInterrupted()) {
                try {
                    Packet packet = packetQueue.take();
                    
                    // Process packet on JavaFX thread
                    Platform.runLater(() -> {
                        String packetInfo = formatPacketInfo(packet);
                        capturedPackets.add(packetInfo);
                        setPacketCount(getPacketCount() + 1);
                        
                        // Limit displayed packets to prevent memory issues
                        if (capturedPackets.size() > 1000) {
                            capturedPackets.remove(0);
                        }
                    });
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;                } catch (Exception e) {
                    System.out.println("Error processing packet: " + e.getMessage());
                }
            }
        });
        
        processingThread.setDaemon(true);
        processingThread.start();
    }
    
    /**
     * Stop packet capture
     */
    public void stopCapture() {
        if (!isCapturing.get()) {
            return;
        }
        
        isCapturing.set(false);
        
        try {
            if (captureThread != null) {
                captureThread.interrupt();
                captureThread = null;
            }
              Platform.runLater(() -> {
                setCapturing(false);
                setStatus("Capture stopped. Total packets: " + getPacketCount());
            });
            
            System.out.println("Packet capture stopped");
            
        } catch (Exception e) {
            System.out.println("Error stopping capture: " + e.getMessage());
        }
    }
    
    /**
     * Format packet information for display
     */
    private String formatPacketInfo(Packet packet) {
        StringBuilder sb = new StringBuilder();
        
        // Add timestamp
        LocalTime now = LocalTime.now();
        sb.append("[").append(now.format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS"))).append("] ");
        
        // Add packet length
        sb.append("Length: ").append(packet.length()).append(" bytes");
        
        // Add protocol and address information
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            sb.append(" | IPv4: ").append(ipPacket.getHeader().getSrcAddr())
              .append(" → ").append(ipPacket.getHeader().getDstAddr());
            
            // Add protocol-specific information
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                sb.append(" | TCP: ").append(tcpPacket.getHeader().getSrcPort())
                  .append(" → ").append(tcpPacket.getHeader().getDstPort());
            } else if (packet.contains(UdpPacket.class)) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                sb.append(" | UDP: ").append(udpPacket.getHeader().getSrcPort())
                  .append(" → ").append(udpPacket.getHeader().getDstPort());
            }
        }
        
        return sb.toString();
    }
    
    /**
     * Refresh available network interfaces
     */
    public void refreshInterfaces() {
        loadAvailableInterfaces();
    }
    
    /**
     * Clear captured packets
     */
    public void clearPackets() {
        capturedPackets.clear();
        setPacketCount(0);
        setStatus("Packets cleared");
    }    /**
     * Get packet queue for external processing
     */
    public BlockingQueue<Packet> getPacketQueue() {
        return packetQueue;
    }
    
    /**
     * Get available interface at index
     */
    PcapNetworkInterface getInterfaceAtIndex(int index) {
        if (index >= 0 && index < availableInterfaces.size()) {
            return availableInterfaces.get(index);
        }
        return null;
    }
      // Property getters and setters
    public boolean isCapturing() { return capturing.get(); }
    BooleanProperty capturingProperty() { return capturing; }
    private void setCapturing(boolean capturing) { this.capturing.set(capturing); }
    
    public String getStatus() { return status.get(); }
    StringProperty statusProperty() { return status; }
    private void setStatus(String status) { this.status.set(status); }
    
    public int getPacketCount() { return packetCount.get(); }
    IntegerProperty packetCountProperty() { return packetCount; }
    private void setPacketCount(int packetCount) { this.packetCount.set(packetCount); }
    
    public String getSelectedInterface() { return selectedInterface.get(); }
    StringProperty selectedInterfaceProperty() { return selectedInterface; }
    private void setSelectedInterface(String selectedInterface) { this.selectedInterface.set(selectedInterface); }
    
    public String getBpfFilter() { return bpfFilter.get(); }
    StringProperty bpfFilterProperty() { return bpfFilter; }
    private void setBpfFilter(String bpfFilter) { this.bpfFilter.set(bpfFilter); }
    
    ObservableList<PcapNetworkInterface> getAvailableInterfaces() { return availableInterfaces; }
    public ObservableList<String> getCapturedPackets() { return capturedPackets; }
    public ObservableList<String> getInterfaceNames() { return interfaceNames; }
    
    // Getters for models
    NetworkInterfaceModel getNifmodel() { return nifmodel; }
    PacketCaptureModel getCapturemodel() { return capturemodel; }
}
