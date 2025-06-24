package com.NetProtector.Models;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import com.NetProtector.Models.Rules.Rule;
import com.NetProtector.Models.Rules.Severity;
import com.NetProtector.Services.NotificationManager;
import com.NetProtector.Services.NotificationServiceFactory;
import com.NetProtector.config.NotificationConfig;
import com.NetProtector.db.DatabaseManager;

/**
 * A detection model for NetProtector that processes packets against rules,
 * generates alerts, and integrates with the NotificationManager.
 *
 * @author Stika
 */
public class DetectionModel {

    private final List<Rule> rules;
    private final List<Alert> alerts;
    private final List<Consumer<Alert>> alertHandlers;
    private boolean isRunning;
    private int nextAlertId;
    private NotificationManager notificationManager; // Added NotificationManager
    private final DatabaseManager dbManager;

    /**
     * Creates a new DetectionModel instance
     */
    public DetectionModel() {
        this.rules = new CopyOnWriteArrayList<>();
        this.alerts = new CopyOnWriteArrayList<>();
        this.alertHandlers = new CopyOnWriteArrayList<>();
        this.isRunning = false;
        this.nextAlertId = 1;
        this.dbManager = new DatabaseManager();

        // Initialize NotificationManager
        try {
            NotificationConfig config = new NotificationConfig(); // Assumes notification.properties is in classpath
            NotificationServiceFactory factory = new NotificationServiceFactory(config);
            this.notificationManager = factory.createNotificationManager();
            System.out.println("Detection Model: NotificationManager initialized successfully.");
        } catch (Exception e) {
            System.err.println("Detection Model: Failed to initialize NotificationManager - " + e.getMessage());
            e.printStackTrace();
            // Optionally, create a dummy NotificationManager or handle this case appropriately
            // For now, it might be null if initialization fails.
        }
    }

    /**
     * Adds a detection rule to the model
     * @param rule The rule to add
     */
    public synchronized void addRule(Rule rule) {
        if (rule != null && !rules.contains(rule)) {
            rules.add(rule);
            System.out.println("Detection Model: Added rule - " + rule.getName());
        }
    }

    /**
     * Removes a detection rule from the model
     * @param rule The rule to remove
     */
    public synchronized void removeRule(Rule rule) {
        if (rule != null) {
            rules.remove(rule);
            System.out.println("Detection Model: Removed rule - " + rule.getName());
        }
    }

    /**
     * Gets an immutable list of all rules
     * @return List of rules
     */
    public List<Rule> getRules() {
        return Collections.unmodifiableList(new ArrayList<>(rules));
    }

    /**
     * Adds an alert handler that will be called when new alerts are generated
     * @param handler The alert handler function
     */
    public void addAlertHandler(Consumer<Alert> handler) {
        if (handler != null) {
            alertHandlers.add(handler);
        }
    }

    /**
     * Removes an alert handler
     * @param handler The handler to remove
     */
    public void removeAlertHandler(Consumer<Alert> handler) {
        alertHandlers.remove(handler);
    }

    /**
     * Processes a single packet against all registered rules
     * @param packet The packet to analyze
     * @return List of alerts generated for this packet
     */
    public List<Alert> processPacket(Packet packet) {
        if (packet == null) {
            System.out.println("Detection Model: Received null packet for processing.");
            return Collections.emptyList();
        }

        List<Alert> generatedAlerts = new ArrayList<>();

        for (Rule rule : rules) {
            try {
                if (rule.verify(packet)) {
                    Alert alert = createAlertFromRule(rule, packet);
                    generatedAlerts.add(alert);
                    alerts.add(alert);
                    dbManager.insertAlert(alert);

                    System.out.println("Detection Model: Alert generated - " + alert.getTitle() +
                                     " [Severity: " + alert.getSeverity() + "]");

                    // Send notification if NotificationManager is available
                    if (notificationManager != null) {
                        try {
                            notificationManager.processAlert(alert);
                            System.out.println("Detection Model: Alert sent to NotificationManager - " + alert.getTitle());
                        } catch (Exception e) {
                            System.err.println("Detection Model: Error sending alert to NotificationManager - " + e.getMessage());
                            e.printStackTrace();
                        }
                    } else {
                        System.out.println("Detection Model: NotificationManager not available. Alert not sent for: " + alert.getTitle());
                    }

                    // Notify local alert handlers
                    for (Consumer<Alert> handler : alertHandlers) {
                        try {
                            handler.accept(alert);
                        } catch (Exception e) {
                            System.err.println("Error in alert handler: " + e.getMessage());
                            e.printStackTrace();
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Error processing rule " + rule.getName() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
        return generatedAlerts;
    }

    /**
     * Continuously processes packets from a queue
     * @param packetQueue The queue to read packets from
     */
    public void processPacketsFromQueue(BlockingQueue<Packet> packetQueue) {
        if (packetQueue == null) {
            System.err.println("Detection Model: Packet queue is null. Cannot start processing.");
            return;
        }

        isRunning = true;
        System.out.println("Detection Model: Started processing packets from queue.");

        while (isRunning && !Thread.currentThread().isInterrupted()) {
            try {
                Packet packet = packetQueue.take(); // Blocking call
                // System.out.println("Detection Model: Took packet from queue for processing."); // Can be noisy
                processPacket(packet);
            } catch (InterruptedException e) {
                System.out.println("Detection Model: Packet processing interrupted.");
                Thread.currentThread().interrupt(); // Preserve interrupt status
                break;
            } catch (Exception e) {
                System.err.println("Detection Model: Error processing packet from queue - " + e.getMessage());
                e.printStackTrace();
            }
        }
        isRunning = false; // Ensure isRunning is false if loop exits
        System.out.println("Detection Model: Stopped processing packets from queue.");
    }

    /**
     * Starts the detection model in a separate thread
     * @param packetQueue The queue to monitor for packets
     * @return The thread running the detection model
     */
    public Thread startDetection(BlockingQueue<Packet> packetQueue) {
        if (isRunning) {
            System.out.println("Detection Model: Detection is already running.");
            return null; // Or return existing thread
        }
        System.out.println("Detection Model: Starting detection thread...");
        if (notificationManager != null) {
            notificationManager.start(); // Start notification services
            System.out.println("Detection Model: NotificationManager started.");
        } else {
            System.out.println("Detection Model: NotificationManager is null, cannot start notification services.");
        }
        Thread detectionThread = new Thread(() -> processPacketsFromQueue(packetQueue),
                                           "DetectionModel-Thread");
        detectionThread.setDaemon(true); // So it doesn't prevent JVM shutdown
        detectionThread.start();
        System.out.println("Detection Model: Detection thread started.");
        return detectionThread;
    }

    /**
     * Stops the detection model
     */
    public synchronized void stopDetection() {
        if (!isRunning) {
            System.out.println("Detection Model: Detection is not running.");
            return;
        }
        isRunning = false;
        // The processing loop will exit on the next iteration due to isRunning flag
        // If the thread is blocked on packetQueue.take(), interrupting it is good practice.
        // The thread reference would be needed here if we want to interrupt it directly.
        // For now, relying on the loop condition.
        if (notificationManager != null) {
            notificationManager.stop(); // Stop notification services
            System.out.println("Detection Model: NotificationManager stopped.");
        }
        System.out.println("Detection Model: Stop requested. Processing will cease shortly.");
    }

    /**
     * Gets all alerts generated by this model
     * @return Immutable list of alerts
     */
    public List<Alert> getAlerts() {
        return Collections.unmodifiableList(new ArrayList<>(alerts));
    }

    /**
     * Gets alerts filtered by severity
     * @param severity The severity to filter by
     * @return List of alerts with the specified severity
     */
    public List<Alert> getAlertsBySeverity(String severity) {
        if (severity == null || severity.trim().isEmpty()) {
            System.out.println("Detection Model: getAlertsBySeverity called with null or empty severity.");
            return Collections.emptyList();
        }
        return alerts.stream()
                    .filter(alert -> severity.equalsIgnoreCase(alert.getSeverity())) // Case-insensitive compare
                    .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }

    /**
     * Gets recent alerts within the specified time window
     * @param minutes Number of minutes to look back
     * @return List of recent alerts
     */
    public List<Alert> getRecentAlerts(int minutes) {
        if (minutes < 0) {
            System.out.println("Detection Model: getRecentAlerts called with negative minutes value.");
            return Collections.emptyList();
        }
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(minutes);
        return alerts.stream()
                    .filter(alert -> alert.getTimestamp().isAfter(cutoff))
                    .collect(ArrayList::new, ArrayList::add, ArrayList::addAll);
    }

    /**
     * Clears all stored alerts
     */
    public synchronized void clearAlerts() {
        alerts.clear();
        System.out.println("Detection Model: Cleared all alerts.");
    }

    /**
     * Gets detection statistics
     * @return Detection statistics as a formatted string
     */
    public String getStatistics() {
        int totalAlertsCount = alerts.size();
        long criticalAlerts = alerts.stream().filter(a -> Severity.CRITICAL.name().equals(a.getSeverity())).count();
        long highAlerts = alerts.stream().filter(a -> Severity.HIGH.name().equals(a.getSeverity())).count();
        long mediumAlerts = alerts.stream().filter(a -> Severity.MEDIUM.name().equals(a.getSeverity())).count();
        long lowAlerts = alerts.stream().filter(a -> Severity.LOW.name().equals(a.getSeverity())).count();

        return String.format(
            "Detection Model Statistics:\n" +
            "Total Rules: %d\n" +
            "Total Alerts: %d\n" +
            "  - Critical: %d\n" +
            "  - High: %d\n" +
            "  - Medium: %d\n" +
            "  - Low: %d\n" +
            "Status: %s",
            rules.size(), totalAlertsCount, criticalAlerts, highAlerts, mediumAlerts, lowAlerts,
            isRunning ? "Running" : "Stopped"
        );
    }

    /**
     * Creates an Alert object from a Rule and Packet
     * @param rule The rule that was triggered
     * @param packet The packet that triggered the rule
     * @return A new Alert object
     */
    private Alert createAlertFromRule(Rule rule, Packet packet) {
        String sourceIp = extractSourceIp(packet);
        String destinationIp = extractDestinationIp(packet);
        String protocol = extractProtocol(packet);
        int port = extractPort(packet);

        return new Alert(
            getNextAlertId(),
            rule.getAlertName(),
            rule.getAlertDescription(),
            severityToString(rule.getSeverity()),
            protocol,
            LocalDateTime.now(),
            sourceIp,
            destinationIp,
            port
        );
    }

    /**
     * Gets the next unique alert ID
     * @return The next alert ID
     */
    private synchronized int getNextAlertId() {
        return nextAlertId++;
    }

    /**
     * Converts Severity enum to string
     * @param severity The severity enum
     * @return String representation of severity
     */
    private String severityToString(Severity severity) {
        return severity != null ? severity.name() : "UNKNOWN";
    }

    /**
     * Extracts source IP from packet
     * @param packet The packet to analyze
     * @return Source IP address or "Unknown"
     */
    private String extractSourceIp(Packet packet) {
        try {
            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket != null && ipPacket.getHeader() != null) {
                return ipPacket.getHeader().getSrcAddr().getHostAddress();
            }
        } catch (Exception e) {
            System.err.println("Detection Model: Error extracting source IP - " + e.getMessage());
        }
        return "Unknown";
    }

    /**
     * Extracts destination IP from packet
     * @param packet The packet to analyze
     * @return Destination IP address or "Unknown"
     */
    private String extractDestinationIp(Packet packet) {
        try {
            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket != null && ipPacket.getHeader() != null) {
                return ipPacket.getHeader().getDstAddr().getHostAddress();
            }
        } catch (Exception e) {
            System.err.println("Detection Model: Error extracting destination IP - " + e.getMessage());
        }
        return "Unknown";
    }

    /**
     * Extracts protocol from packet
     * @param packet The packet to analyze
     * @return Protocol name or "Unknown"
     */
    private String extractProtocol(Packet packet) {
        try {
            if (packet.get(TcpPacket.class) != null) {
                return "TCP";
            } else if (packet.get(UdpPacket.class) != null) {
                return "UDP";
            } else {
                IpPacket ipPacket = packet.get(IpPacket.class);
                if (ipPacket != null && ipPacket.getHeader() != null && ipPacket.getHeader().getProtocol() != null) {
                    return ipPacket.getHeader().getProtocol().name();
                }
            }
        } catch (Exception e) {
            System.err.println("Detection Model: Error extracting protocol - " + e.getMessage());
        }
        return "Unknown";
    }

    /**
     * Extracts port from packet (destination port for TCP/UDP)
     * @param packet The packet to analyze
     * @return Port number or 0 if not available
     */
    private int extractPort(Packet packet) {
        try {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            if (tcpPacket != null && tcpPacket.getHeader() != null && tcpPacket.getHeader().getDstPort() != null) {
                return tcpPacket.getHeader().getDstPort().valueAsInt();
            }

            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null && udpPacket.getHeader() != null && udpPacket.getHeader().getDstPort() != null) {
                return udpPacket.getHeader().getDstPort().valueAsInt();
            }
        } catch (Exception e) {
            System.err.println("Detection Model: Error extracting port - " + e.getMessage());
        }
        return 0;
    }

    /**
     * Checks if the detection model is currently running
     * @return true if running, false otherwise
     */
    public boolean isRunning() {
        return isRunning;
    }

    /**
     * Gets the total number of rules registered
     * @return Number of rules
     */
    public int getRuleCount() {
        return rules.size();
    }

    /**
     * Gets the total number of alerts generated
     * @return Number of alerts
     */
    public int getAlertCount() {
        return alerts.size();
    }
}
