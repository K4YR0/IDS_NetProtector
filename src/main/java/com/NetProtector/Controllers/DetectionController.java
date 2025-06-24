package com.NetProtector.Controllers;

import com.NetProtector.Models.Alert;
import com.NetProtector.Models.DetectionModel;
import com.NetProtector.Models.Rules.*;
import javafx.application.Platform;
import javafx.beans.property.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.packet.Packet;

import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ResourceBundle;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Controller for the Detection system in NetProtector.
 * Manages the DetectionModel, rules, and provides real-time detection monitoring.
 * 
 * @author Stika
 */
public class DetectionController implements Initializable {

    // FXML Controls
    @FXML private Button startDetectionBtn;
    @FXML private Button stopDetectionBtn;
    @FXML private Button clearAlertsBtn;
    @FXML private Button addRuleBtn;
    @FXML private Button removeRuleBtn;
    
    @FXML private Label statusLabel;
    @FXML private Label totalRulesLabel;
    @FXML private Label totalAlertsLabel;
    @FXML private Label lastAlertLabel;
    
    @FXML private TableView<Rule> rulesTableView;
    @FXML private TableColumn<Rule, String> ruleNameColumn;
    @FXML private TableColumn<Rule, String> ruleSeverityColumn;
    @FXML private TableColumn<Rule, String> ruleDescriptionColumn;
    
    @FXML private TableView<Alert> alertsTableView;
    @FXML private TableColumn<Alert, Integer> alertIdColumn;
    @FXML private TableColumn<Alert, String> alertTitleColumn;
    @FXML private TableColumn<Alert, String> alertSeverityColumn;
    @FXML private TableColumn<Alert, LocalDateTime> alertTimestampColumn;
    @FXML private TableColumn<Alert, String> alertSourceIpColumn;
    @FXML private TableColumn<Alert, String> alertDestinationIpColumn;
    @FXML private TableColumn<Alert, String> alertProtocolColumn;
    
    @FXML private ComboBox<String> severityFilterCombo;
    @FXML private TextField searchTextField;
    @FXML private TextArea statisticsTextArea;
    
    // Properties for data binding
    private final BooleanProperty detectionRunning = new SimpleBooleanProperty(false);
    private final StringProperty currentStatus = new SimpleStringProperty("Stopped");
    private final IntegerProperty totalRules = new SimpleIntegerProperty(0);
    private final IntegerProperty totalAlerts = new SimpleIntegerProperty(0);
    private final StringProperty lastAlert = new SimpleStringProperty("None");
    
    // Detection components
    private DetectionModel detectionModel;
    private Thread detectionThread;
    private BlockingQueue<Packet> packetQueue;
    
    // Observable lists for UI
    private final ObservableList<Rule> rulesData = FXCollections.observableArrayList();
    private final ObservableList<Alert> alertsData = FXCollections.observableArrayList();
    private final ObservableList<Alert> filteredAlertsData = FXCollections.observableArrayList();

    /**
     * Constructor for non-JavaFX usage (for testing and console applications)
     */
    public DetectionController() {
        initializeDetectionModel();
        loadDefaultRules();
        System.out.println("Detection Controller initialized for non-JavaFX usage");
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        initializeDetectionModel();
        initializeUI();
        setupTableColumns();
        setupDataBinding();
        setupEventHandlers();
        loadDefaultRules();
        updateStatistics();
        
        System.out.println("Detection Controller initialized successfully");
    }    /**
     * Initializes the detection model and packet queue
     */
    private void initializeDetectionModel() {
        detectionModel = new DetectionModel();
        packetQueue = new LinkedBlockingQueue<>();
        
        // Add alert handler to update UI when new alerts are generated
        detectionModel.addAlertHandler(alert -> {
            // Check if we're in JavaFX context
            if (isJavaFXContext()) {
                Platform.runLater(() -> {
                    alertsData.add(alert);
                    applyFilters();
                    updateAlertStatistics();
                    lastAlert.set(alert.getTitle() + " at " + 
                        alert.getTimestamp().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
                });
            } else {
                // For non-JavaFX context, just print to console
                System.out.println("Alert generated: " + alert.getTitle() + " [" + alert.getSeverity() + "]");
            }
        });
    }
    
    /**
     * Check if we're running in JavaFX context
     */
    private boolean isJavaFXContext() {
        try {
            // Check if JavaFX Platform is initialized
            Platform.runLater(() -> {});
            return true;
        } catch (IllegalStateException e) {
            return false;
        }
    }

    /**
     * Initializes UI components
     */
    private void initializeUI() {
        // Setup severity filter combo
        severityFilterCombo.setItems(FXCollections.observableArrayList(
            "All", "CRITICAL", "HIGH", "MEDIUM", "LOW"
        ));
        severityFilterCombo.setValue("All");
        
        // Setup table views
        rulesTableView.setItems(rulesData);
        alertsTableView.setItems(filteredAlertsData);
        
        // Initial button states
        startDetectionBtn.setDisable(false);
        stopDetectionBtn.setDisable(true);
        removeRuleBtn.setDisable(true);
    }

    /**
     * Sets up table columns
     */
    private void setupTableColumns() {
        // Rules table columns
        ruleNameColumn.setCellValueFactory(cellData -> 
            new SimpleStringProperty(cellData.getValue().getName()));
        ruleSeverityColumn.setCellValueFactory(cellData -> 
            new SimpleStringProperty(cellData.getValue().getSeverity().name()));
        ruleDescriptionColumn.setCellValueFactory(cellData -> 
            new SimpleStringProperty(cellData.getValue().getAlertDescription()));
        
        // Alerts table columns
        alertIdColumn.setCellValueFactory(new PropertyValueFactory<>("id"));
        alertTitleColumn.setCellValueFactory(new PropertyValueFactory<>("title"));
        alertSeverityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
        alertTimestampColumn.setCellValueFactory(new PropertyValueFactory<>("timestamp"));
        alertSourceIpColumn.setCellValueFactory(new PropertyValueFactory<>("sourceIp"));
        alertDestinationIpColumn.setCellValueFactory(new PropertyValueFactory<>("destinationIp"));
        alertProtocolColumn.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        
        // Format timestamp column
        alertTimestampColumn.setCellFactory(column -> new TableCell<Alert, LocalDateTime>() {
            private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            
            @Override
            protected void updateItem(LocalDateTime item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(formatter.format(item));
                }
            }
        });
    }

    /**
     * Sets up data binding between properties and UI components
     */
    private void setupDataBinding() {
        // Bind button states
        startDetectionBtn.disableProperty().bind(detectionRunning);
        stopDetectionBtn.disableProperty().bind(detectionRunning.not());
        
        // Bind labels
        statusLabel.textProperty().bind(currentStatus);
        totalRulesLabel.textProperty().bind(totalRules.asString());
        totalAlertsLabel.textProperty().bind(totalAlerts.asString());
        lastAlertLabel.textProperty().bind(lastAlert);
        
        // Update rule count when rules change
        rulesData.addListener((javafx.collections.ListChangeListener<Rule>) change -> {
            totalRules.set(rulesData.size());
            updateStatistics();
        });
    }

    /**
     * Sets up event handlers for UI components
     */
    private void setupEventHandlers() {
        // Table selection handlers
        rulesTableView.getSelectionModel().selectedItemProperty().addListener(
            (obs, oldSelection, newSelection) -> {
                removeRuleBtn.setDisable(newSelection == null);
            });
        
        // Filter handlers
        severityFilterCombo.setOnAction(e -> applyFilters());
        searchTextField.textProperty().addListener((obs, oldText, newText) -> applyFilters());
    }

    /**
     * Loads default detection rules
     */
    private void loadDefaultRules() {
        // Add the rules we created earlier
        detectionModel.addRule(new DdosDetectionRule());
        detectionModel.addRule(new SqlInjectionRule());
        detectionModel.addRule(new BruteForceDetectionRule());
        detectionModel.addRule(new DnsTunnelingRule());
        detectionModel.addRule(new MaliciousIpRule());
        detectionModel.addRule(new IcmpFloodRule());
        detectionModel.addRule(new DataExfiltrationRule());
        detectionModel.addRule(new UnwantedTrafficRule());
        
        // Add some existing rules
        detectionModel.addRule(new DNSScan());
        detectionModel.addRule(new TcpSynScanRule());
        detectionModel.addRule(new PingDetectRule());
        detectionModel.addRule(new SuspiciousPortRule());
        detectionModel.addRule(new SimplePayloadStringRule());
        
        // Update UI
        refreshRulesTable();
    }

    /**
     * Refreshes the rules table with current rules from the model
     */
    private void refreshRulesTable() {
        rulesData.clear();
        rulesData.addAll(detectionModel.getRules());
    }

    /**
     * Starts the detection process
     */
    @FXML
    private void handleStartDetection() {
        startDetection();
    }
    
    /**
     * Public method to start detection (for non-JavaFX usage)
     */
    public void startDetection() {
        if (!detectionModel.isRunning()) {
            detectionThread = detectionModel.startDetection(packetQueue);
            detectionRunning.set(true);
            currentStatus.set("Running");
            
            System.out.println("Detection started with " + detectionModel.getRuleCount() + " rules");
            
            // Only start simulation if in JavaFX context
            if (isJavaFXContext()) {
                startPacketSimulation();
            }
        }
    }

    /**
     * Stops the detection process
     */
    @FXML
    private void handleStopDetection() {
        stopDetection();
    }
    
    /**
     * Public method to stop detection (for non-JavaFX usage)
     */
    public void stopDetection() {
        if (detectionModel.isRunning()) {
            detectionModel.stopDetection();
            if (detectionThread != null) {
                detectionThread.interrupt();
            }
            detectionRunning.set(false);
            currentStatus.set("Stopped");
            
            System.out.println("Detection stopped");
        }
    }

    /**
     * Clears all alerts
     */
    @FXML
    private void handleClearAlerts() {
        detectionModel.clearAlerts();
        alertsData.clear();
        filteredAlertsData.clear();
        updateAlertStatistics();
        lastAlert.set("None");
        
        System.out.println("All alerts cleared");
    }    /**
     * Adds a new rule (placeholder for future implementation)
     */
    @FXML
    private void handleAddRule() {
        // This could open a dialog to create custom rules
        // For now, just show a placeholder message
        javafx.scene.control.Alert alert = new javafx.scene.control.Alert(javafx.scene.control.Alert.AlertType.INFORMATION);
        alert.setTitle("Add Rule");
        alert.setHeaderText("Add New Detection Rule");
        alert.setContentText("This feature will allow you to create custom detection rules.");
        alert.showAndWait();
    }

    /**
     * Removes the selected rule
     */
    @FXML
    private void handleRemoveRule() {
        Rule selectedRule = rulesTableView.getSelectionModel().getSelectedItem();
        if (selectedRule != null) {
            detectionModel.removeRule(selectedRule);
            refreshRulesTable();
            System.out.println("Removed rule: " + selectedRule.getName());
        }
    }

    /**
     * Applies filters to the alerts table
     */
    private void applyFilters() {
        
        filteredAlertsData.clear();
        
        String severityFilter = severityFilterCombo.getValue();
        String searchFilter = searchTextField.getText().toLowerCase();
        
        for (Alert alert : alertsData) {
            boolean matchesSeverity = "All".equals(severityFilter) || 
                                    severityFilter.equals(alert.getSeverity());
            boolean matchesSearch = searchFilter.isEmpty() || 
                                  alert.getTitle().toLowerCase().contains(searchFilter) ||
                                  alert.getDescription().toLowerCase().contains(searchFilter) ||
                                  alert.getSourceIp().toLowerCase().contains(searchFilter) ||
                                  alert.getDestinationIp().toLowerCase().contains(searchFilter);
            
            if (matchesSeverity && matchesSearch) {
                filteredAlertsData.add(alert);
            }
        }
    }

    /**
     * Updates alert statistics
     */
    private void updateAlertStatistics() {
        totalAlerts.set(alertsData.size());
    }

    /**
     * Updates the statistics text area
     */
    private void updateStatistics() {
        if (statisticsTextArea != null) {
            Platform.runLater(() -> {
                statisticsTextArea.setText(detectionModel.getStatistics());
            });
        }
    }

    /**
     * Simulates packet injection for demonstration purposes
     * In production, this would be replaced with real packet capture integration
     */
    private void startPacketSimulation() {
        Thread simulationThread = new Thread(() -> {
            try {
                Thread.sleep(2000); // Wait 2 seconds before starting simulation
                
                // This is just for demonstration - in real usage, 
                // packets would come from PacketCaptureController
                System.out.println("Packet simulation started (for demonstration)");
                
                // In production, you would integrate with PacketCaptureController:
                // PacketCaptureController packetController = new PacketCaptureController();
                // packetController.setPacketQueue(this.packetQueue);
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        simulationThread.setDaemon(true);
        simulationThread.start();
    }    /**
     * Gets the packet queue for integration with packet capture
     * @return The packet queue
     */
    public BlockingQueue<Packet> getPacketQueue() {
        return packetQueue;
    }

    /**
     * Gets the detection model
     * @return The detection model
     */
    public DetectionModel getDetectionModel() {
        return detectionModel;
    }

    /**
     * Injects a packet into the detection system (for testing or external integration)
     * @param packet The packet to process
     */
    void injectPacket(Packet packet) {
        if (packet != null) {
            try {
                packetQueue.put(packet);
            } catch (InterruptedException e) {
                System.err.println("Failed to inject packet: " + e.getMessage());
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Gets detection running status
     * @return true if detection is running
     */
    public boolean isDetectionRunning() {
        return detectionRunning.get();
    }    /**
     * Gets detection running property for binding
     * @return Detection running property
     */
    BooleanProperty detectionRunningProperty() {
        return detectionRunning;
    }

    /**
     * Gets total alerts count
     * @return Number of alerts
     */
    public int getTotalAlerts() {
        return totalAlerts.get();
    }

    /**
     * Gets total rules count
     * @return Number of rules
     */
    public int getTotalRules() {
        return totalRules.get();
    }

    /**
     * Cleanup method called when controller is destroyed
     */
    public void cleanup() {
        if (detectionModel != null && detectionModel.isRunning()) {
            detectionModel.stopDetection();
        }
        if (detectionThread != null) {
            detectionThread.interrupt();
        }
        System.out.println("Detection Controller cleaned up");
    }
}
