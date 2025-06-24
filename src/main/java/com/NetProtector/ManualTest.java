package com.NetProtector;

import com.NetProtector.Controllers.DetectionController;
import com.NetProtector.Controllers.PacketCaptureController;
import com.NetProtector.Models.Alert;
import com.NetProtector.Models.DetectionModel;
import org.pcap4j.packet.Packet;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.BlockingQueue;

/**
 * Manual test class for testing PacketCaptureController and DetectionController integration.
 * This test demonstrates the core functionality of the NetProtector system in a console environment.
 * 
 * @author Stika
 */
public class ManualTest {
    
    private static PacketCaptureController packetController;
    private static DetectionController detectionController;
    private static Thread alertMonitorThread;
    private static volatile boolean running = true;
    
    public static void main(String[] args) {
        System.out.println("=== NetProtector Manual Test ===");
        System.out.println("Testing PacketCaptureController and DetectionController integration");
        System.out.println();
        
        try {
            // Step 1: Initialize controllers
            initializeControllers();
            
            // Step 2: List available network interfaces
            listNetworkInterfaces();
            
            // Step 3: Select interface
            int selectedInterface = selectInterface();
            if (selectedInterface == -1) {
                System.out.println("No interface selected. Exiting...");
                return;
            }
            
            // Step 4: Start packet capture
            startPacketCapture(selectedInterface);
            
            // Step 5: Initialize detection controller with packet queue
            initializeDetection();
            
            // Step 6: Start detection engine
            startDetectionEngine();
            
            // Step 7: Start alert monitoring in separate thread
            startAlertMonitoring();
            
            // Step 8: Run for specified time or until user stops
            runTest();
            
        } catch (Exception e) {
            System.err.println("Error during test execution: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Step 9: Cleanup
            cleanup();
        }
    }
    
    /**
     * Initialize the controllers
     */
    private static void initializeControllers() {
        System.out.println("Step 1: Initializing controllers...");
        
        // Initialize packet capture controller
        packetController = new PacketCaptureController();
        System.out.println("✓ PacketCaptureController initialized");
        
        // Initialize detection controller (without JavaFX dependency)
        detectionController = new DetectionController();
        System.out.println("✓ DetectionController initialized");
        
        System.out.println();
    }
    
    /**
     * List all available network interfaces
     */
    private static void listNetworkInterfaces() {
        System.out.println("Step 2: Listing available network interfaces...");
        
        List<String> interfaceNames = packetController.getInterfaceNames();
        
        if (interfaceNames.isEmpty()) {
            System.out.println("No network interfaces found!");
            return;
        }
        
        System.out.println("Available interfaces:");
        for (int i = 0; i < interfaceNames.size(); i++) {
            System.out.printf("[%d] %s%n", i, interfaceNames.get(i));
        }
        System.out.println();
    }
    
    /**
     * Allow user to select a network interface
     */
    private static int selectInterface() {
        System.out.println("Step 3: Selecting network interface...");
        
        List<String> interfaceNames = packetController.getInterfaceNames();
        if (interfaceNames.isEmpty()) {
            return -1;
        }
          Scanner scanner = new Scanner(System.in);
        System.out.print("Enter interface number (0-" + (interfaceNames.size() - 1) + "): ");
        
        try {
            int selection = scanner.nextInt();
            if (selection >= 0 && selection < interfaceNames.size()) {
                System.out.println("Selected: " + interfaceNames.get(selection));
                System.out.println();
                return selection;
            } else {
                System.out.println("Invalid selection!");
                return -1;
            }
        } catch (Exception e) {
            System.out.println("Invalid input!");
            return -1;
        } finally {
            // Don't close scanner here as it will close System.in
        }
    }
    
    /**
     * Start packet capture on selected interface
     */
    private static void startPacketCapture(int interfaceIndex) {
        System.out.println("Step 4: Starting packet capture...");
        
        // Start packet capture in a separate thread
        Thread captureThread = new Thread(() -> {
            try {
                // Use empty filter to capture all packets
                packetController.startCapture(interfaceIndex, "");
                System.out.println("✓ Packet capture started successfully");
            } catch (Exception e) {
                System.err.println("Failed to start packet capture: " + e.getMessage());
            }
        });
        
        captureThread.setDaemon(true);
        captureThread.start();
        
        // Wait a moment for capture to initialize
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        System.out.println();
    }
    
    /**
     * Initialize detection controller with packet queue from capture controller
     */
    private static void initializeDetection() {
        System.out.println("Step 5: Initializing detection with packet queue...");
        
        // Get the packet queue from capture controller
        BlockingQueue<Packet> packetQueue = packetController.getPacketQueue();
          // Get the detection model and set its packet queue
        // The detection controller already has its own packet queue, 
        // but we need to bridge the packets from capture to detection
        startPacketBridge(packetQueue, detectionController.getPacketQueue());
        
        System.out.println("✓ Detection initialized with packet queue");
        System.out.println("✓ Packet bridge started");
        System.out.println();
    }
    
    /**
     * Bridge packets from capture queue to detection queue
     */
    private static void startPacketBridge(BlockingQueue<Packet> sourceQueue, 
                                         BlockingQueue<Packet> targetQueue) {
        Thread bridgeThread = new Thread(() -> {
            System.out.println("Packet bridge thread started");
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    Packet packet = sourceQueue.take();
                    targetQueue.offer(packet);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    System.err.println("Error in packet bridge: " + e.getMessage());
                }
            }
            System.out.println("Packet bridge thread stopped");
        });
        
        bridgeThread.setDaemon(true);
        bridgeThread.start();
    }
      /**
     * Start the detection engine
     */
    private static void startDetectionEngine() {
        System.out.println("Step 6: Starting detection engine...");
        
        // Start detection using the public method
        detectionController.startDetection();
        
        System.out.println("✓ Detection engine started");
        System.out.println();
    }
    
    /**
     * Start monitoring alerts in a separate thread
     */
    private static void startAlertMonitoring() {
        System.out.println("Step 7: Starting alert monitoring...");
        
        alertMonitorThread = new Thread(() -> {
            System.out.println("Alert monitoring thread started");
            DetectionModel detectionModel = detectionController.getDetectionModel();
            int lastAlertCount = 0;
            
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    List<Alert> currentAlerts = detectionModel.getAlerts();
                    
                    // Check for new alerts
                    if (currentAlerts.size() > lastAlertCount) {
                        // Display new alerts
                        for (int i = lastAlertCount; i < currentAlerts.size(); i++) {
                            Alert alert = currentAlerts.get(i);
                            displayAlert(alert);
                        }
                        lastAlertCount = currentAlerts.size();
                    }
                    
                    // Sleep for a short period before checking again
                    Thread.sleep(1000);
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    System.err.println("Error in alert monitoring: " + e.getMessage());
                }
            }
            System.out.println("Alert monitoring thread stopped");
        });
        
        alertMonitorThread.setDaemon(true);
        alertMonitorThread.start();
        
        System.out.println("✓ Alert monitoring started");
        System.out.println();
    }
    
    /**
     * Display an alert to the console
     */
    private static void displayAlert(Alert alert) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        System.out.println("🚨 ALERT DETECTED:");
        System.out.println("   ID: " + alert.getId());
        System.out.println("   Title: " + alert.getTitle());
        System.out.println("   Severity: " + alert.getSeverity());
        System.out.println("   Time: " + alert.getTimestamp().format(formatter));
        System.out.println("   Source IP: " + alert.getSourceIp());
        System.out.println("   Destination IP: " + alert.getDestinationIp());
        System.out.println("   Protocol: " + alert.getProtocol());
        System.out.println("   Description: " + alert.getDescription());
        System.out.println();
    }
    
    /**
     * Run the test and wait for user input to stop
     */
    private static void runTest() {
        System.out.println("Step 8: Running test...");
        System.out.println("NetProtector is now capturing packets and monitoring for threats.");
        System.out.println("Press Enter to stop the test...");
        System.out.println();
        
        // Display status information
        displayStatus();
          // Wait for user input
        try (Scanner scanner = new Scanner(System.in)) {
            scanner.nextLine();
        }
        
        System.out.println("Stopping test...");
    }
    
    /**
     * Display current status information
     */
    private static void displayStatus() {
        Thread statusThread = new Thread(() -> {
            while (running) {
                try {
                    // Display packet count and detection status
                    int packetCount = packetController.getPacketCount();
                    boolean capturing = packetController.isCapturing();
                    String status = packetController.getStatus();
                    
                    DetectionModel detectionModel = detectionController.getDetectionModel();
                    int alertCount = detectionModel.getAlerts().size();
                    int ruleCount = detectionModel.getRuleCount();
                    
                    System.out.printf("\r[Packets: %d | Capturing: %s | Alerts: %d | Rules: %d | Status: %s]",
                        packetCount, capturing, alertCount, ruleCount, status);
                    
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    // Ignore minor errors in status display
                }
            }
        });
        
        statusThread.setDaemon(true);
        statusThread.start();
    }
    
    /**
     * Cleanup resources and stop all threads
     */
    private static void cleanup() {
        System.out.println("\nStep 9: Cleaning up...");
        
        running = false;
        
        try {
            // Stop packet capture
            if (packetController != null) {
                packetController.stopCapture();
                System.out.println("✓ Packet capture stopped");
            }
              // Stop detection
            if (detectionController != null) {
                detectionController.stopDetection();
                System.out.println("✓ Detection engine stopped");
            }
            
            // Stop alert monitoring
            if (alertMonitorThread != null && alertMonitorThread.isAlive()) {
                alertMonitorThread.interrupt();
                System.out.println("✓ Alert monitoring stopped");
            }
            
            // Display final statistics
            displayFinalStatistics();
            
        } catch (Exception e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }
        
        System.out.println("✓ Cleanup completed");
        System.out.println("Test finished.");
    }
    
    /**
     * Display final test statistics
     */
    private static void displayFinalStatistics() {
        System.out.println("\n=== Test Results ===");
        
        if (packetController != null) {
            System.out.println("Total packets captured: " + packetController.getPacketCount());
        }
        
        if (detectionController != null) {
            DetectionModel detectionModel = detectionController.getDetectionModel();
            List<Alert> alerts = detectionModel.getAlerts();
            System.out.println("Total alerts generated: " + alerts.size());
            System.out.println("Total rules loaded: " + detectionModel.getRuleCount());
            
            if (!alerts.isEmpty()) {
                System.out.println("\nAlert Summary:");
                alerts.forEach(alert -> {
                    System.out.printf("  - %s [%s] at %s%n", 
                        alert.getTitle(), 
                        alert.getSeverity(),
                        alert.getTimestamp().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
                });
            }
        }
        
        System.out.println("==================");
    }
}
