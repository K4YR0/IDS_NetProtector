package com.NetProtector.Controllers;

import com.NetProtector.Models.Alert;
import com.NetProtector.Models.DetectionModel;
import com.NetProtector.Services.ReportService;
import com.NetProtector.db.DatabaseManager;
import javafx.animation.FadeTransition;
import javafx.animation.ScaleTransition;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.effect.DropShadow;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;
import org.pcap4j.packet.Packet;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javafx.scene.Scene;
import javafx.scene.chart.*;
import javafx.collections.FXCollections;
import java.util.concurrent.ConcurrentLinkedQueue;
import javafx.collections.transformation.FilteredList;
import javafx.beans.binding.Bindings;

public class NetProtectorMainController implements Initializable {

    // FXML Controls for Main View
    @FXML
    private ListView<String> interfaceListView;
    @FXML
    private TextField filterTextField;
    @FXML
    private Button refreshButton;
    @FXML
    private Button startCaptureButton;
    @FXML
    private Button stopCaptureButton;
    @FXML
    private Button startDetectionButton;
    @FXML
    private Button stopDetectionButton;
    @FXML
    private Button clearAlertsButton;
    @FXML
    private Button exportAlertsButton;
    @FXML
    private Button generatePdfReportButton;
    @FXML
    private Button generateCsvReportButton;

    // Statistics Labels for Main View
    @FXML
    private Label packetCountLabel;
    @FXML
    private Label captureStatusLabel;
    @FXML
    private Label detectionStatusLabel;
    @FXML
    private Label alertCountLabel;
    @FXML
    private Label ruleCountLabel;
    @FXML
    private Label statusLabel;
    @FXML
    private Label timestampLabel;
    @FXML
    private Label performanceLabel;
    @FXML
    private ProgressBar performanceBar;

    // Alert Table for Main View
    @FXML
    private TableView<Alert> alertTableView;
    @FXML
    private TableColumn<Alert, String> alertTimeColumn;
    @FXML
    private TableColumn<Alert, String> alertTitleColumn;
    @FXML
    private TableColumn<Alert, String> alertSeverityColumn;
    @FXML
    private TableColumn<Alert, String> alertSourceColumn;
    @FXML
    private TableColumn<Alert, String> alertDestColumn;
    @FXML
    private TableColumn<Alert, String> alertProtocolColumn;
    @FXML
    private TableColumn<Alert, Integer> alertPortColumn;
    @FXML
    private TableColumn<Alert, String> alertDescColumn;

    // New FXML controls for enhanced filtering
    @FXML
    private ComboBox<String> quickFilterComboBox;
    @FXML
    private Button applyQuickFilterButton;

    // Real-time charts
    @FXML
    private LineChart<String, Number> packetRateChart;
    @FXML
    private CategoryAxis packetRateXAxis;
    @FXML
    private NumberAxis packetRateYAxis;

    @FXML
    private PieChart protocolDistributionChart;

    @FXML
    private AreaChart<String, Number> alertTrendChart;
    @FXML
    private CategoryAxis alertTrendXAxis;
    @FXML
    private NumberAxis alertTrendYAxis;

    // Chart data
    private XYChart.Series<String, Number> packetRateSeries;
    private XYChart.Series<String, Number> alertTrendSeries;
    private final ConcurrentLinkedQueue<Integer> packetRateHistory = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<Integer> alertHistory = new ConcurrentLinkedQueue<>();
    private final Map<String, Integer> protocolCounts = new HashMap<>();
    private int lastPacketCount = 0;
    private int lastAlertCount = 0;

    // Controllers
    private PacketCaptureController packetController;
    private DetectionController detectionController;
    private ReportService reportService;
    private DatabaseManager dbManager;

    // Notification Settings Controller - properly aligned with FXML fx:id
    @FXML
    private NotificationSettingsController notificationSettingsViewController;

    // Data
    private ObservableList<Alert> alertData;
    private ScheduledExecutorService statusUpdateService;
    private Thread packetBridgeThread;
    private volatile boolean running = true;

    @FXML
    private TextField alertSearchField;

    @FXML
    private Button clearSearchButton;

    // Add filtered list for alerts
    private FilteredList<Alert> filteredAlerts;

    // Add these FXML controls for navigation
    @FXML
    private Button navDashboardBtn;
    @FXML
    private Button navMonitoringBtn;
    @FXML
    private Button navAlertsBtn;
    @FXML
    private Button navStatisticsBtn;
    @FXML
    private Button navSettingsBtn;
    @FXML
    private Button navExitBtn;

    // Add these for the different views
    @FXML
    private VBox dashboardView;
    @FXML
    private VBox monitoringView;
    @FXML
    private VBox alertsView;
    @FXML
    private VBox statisticsView;
    @FXML
    private VBox settingsView;

    // Add these for status indicators
    @FXML
    private Label captureStatusIcon;
    @FXML
    private Label detectionStatusIcon;
    @FXML
    private Label alertCountBadge;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        System.out.println("NetProtectorMainController: Initializing with enhanced UI...");

        // Apply CSS styles if available - do this FIRST
        applyStylesheet();
        applyInitialStyles();

        initializeCoreControllers();
        initializeUIComponents();
        initializeCharts();
        initializeQuickFilters();
        startStatusUpdates();
        loadNetworkInterfaces();
        setupAnimations();
        setupTooltips();

        // Check if NotificationSettingsController was injected properly
        if (notificationSettingsViewController != null) {
            System.out.println("NetProtectorMainController: NotificationSettingsController injected successfully.");
        } else {
            System.out.println(
                    "NetProtectorMainController: NotificationSettingsController was NOT injected. Check FXML fx:id 'notificationSettingsView'.");
        }

        updateStatusWithAnimation("🟢 Application initialized. Ready to secure your network!");
        System.out.println("NetProtectorMainController: Enhanced initialization complete.");

        // Initialize search functionality
        setupAlertSearch();

        // Set up clear search button
        clearSearchButton.setOnAction(e -> clearSearch());

        setupAlertTable();

        // Setup alert table styling
        setupAlertTableRowStyling();
    }

    private void applyStylesheet() {
        try {
            // Try multiple approaches to apply the stylesheet
            if (navDashboardBtn != null && navDashboardBtn.getScene() != null) {
                String css = getClass().getResource("/css/styles.css").toExternalForm();
                navDashboardBtn.getScene().getStylesheets().clear(); // Clear existing stylesheets
                navDashboardBtn.getScene().getStylesheets().add(css);
                System.out.println("CSS stylesheet applied successfully: " + css);
            }
        } catch (Exception e) {
            System.err.println("Could not apply CSS stylesheet: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void applyInitialStyles() {
        // Force apply some critical styles programmatically
        if (navDashboardBtn != null) {
            navDashboardBtn.getStyleClass().add("nav-btn-active");
        }

        // Set initial performance bar style
        if (performanceBar != null) {
            performanceBar.getStyleClass().add("performance-bar-excellent");
        }

        // Apply status styles
        updateSidebarStatus();
    }

    private void setupAnimations() {
        // Add subtle hover animations to all buttons
        if (startCaptureButton != null)
            addHoverAnimation(startCaptureButton);
        if (stopCaptureButton != null)
            addHoverAnimation(stopCaptureButton);
        if (startDetectionButton != null)
            addHoverAnimation(startDetectionButton);
        if (stopDetectionButton != null)
            addHoverAnimation(stopDetectionButton);
        if (clearAlertsButton != null)
            addHoverAnimation(clearAlertsButton);
        if (exportAlertsButton != null)
            addHoverAnimation(exportAlertsButton);
        if (generatePdfReportButton != null)
            addHoverAnimation(generatePdfReportButton);
        if (generateCsvReportButton != null)
            addHoverAnimation(generateCsvReportButton);
        if (refreshButton != null)
            addHoverAnimation(refreshButton);
    }

    private void addHoverAnimation(Button button) {
        button.setOnMouseEntered(e -> {
            ScaleTransition scaleIn = new ScaleTransition(Duration.millis(150), button);
            scaleIn.setToX(1.05);
            scaleIn.setToY(1.05);
            scaleIn.play();
        });

        button.setOnMouseExited(e -> {
            ScaleTransition scaleOut = new ScaleTransition(Duration.millis(150), button);
            scaleOut.setToX(1.0);
            scaleOut.setToY(1.0);
            scaleOut.play();
        });
    }

    private void initializeQuickFilters() {
        if (quickFilterComboBox != null) {
            quickFilterComboBox.setItems(FXCollections.observableArrayList(
                    "All Traffic",
                    "HTTP Traffic (port 80)",
                    "HTTPS Traffic (port 443)",
                    "SSH Traffic (port 22)",
                    "FTP Traffic (port 21)",
                    "DNS Traffic (port 53)",
                    "SMTP Traffic (port 25)",
                    "POP3 Traffic (port 110)",
                    "IMAP Traffic (port 143)",
                    "TCP Traffic Only",
                    "UDP Traffic Only",
                    "ICMP Traffic Only",
                    "Local Network (192.168.x.x)",
                    "External Traffic",
                    "High Port Traffic (>1024)"));
            quickFilterComboBox.setValue("All Traffic");
        }

        if (applyQuickFilterButton != null) {
            applyQuickFilterButton.setOnAction(e -> applyQuickFilter());
        }
    }

    private void applyQuickFilter() {
        if (quickFilterComboBox == null || filterTextField == null) {
            return;
        }

        String selectedFilter = quickFilterComboBox.getValue();
        String filterExpression = "";

        switch (selectedFilter) {
            case "All Traffic":
                filterExpression = "";
                break;
            case "HTTP Traffic (port 80)":
                filterExpression = "port 80";
                break;
            case "HTTPS Traffic (port 443)":
                filterExpression = "port 443";
                break;
            case "SSH Traffic (port 22)":
                filterExpression = "port 22";
                break;
            case "FTP Traffic (port 21)":
                filterExpression = "port 21";
                break;
            case "DNS Traffic (port 53)":
                filterExpression = "port 53";
                break;
            case "SMTP Traffic (port 25)":
                filterExpression = "port 25";
                break;
            case "POP3 Traffic (port 110)":
                filterExpression = "port 110";
                break;
            case "IMAP Traffic (port 143)":
                filterExpression = "port 143";
                break;
            case "TCP Traffic Only":
                filterExpression = "tcp";
                break;
            case "UDP Traffic Only":
                filterExpression = "udp";
                break;
            case "ICMP Traffic Only":
                filterExpression = "icmp";
                break;
            case "Local Network (192.168.x.x)":
                filterExpression = "net 192.168.0.0/16";
                break;
            case "External Traffic":
                filterExpression = "not net 192.168.0.0/16 and not net 10.0.0.0/8 and not net 172.16.0.0/12";
                break;
            case "High Port Traffic (>1024)":
                filterExpression = "portrange 1024-65535";
                break;
            default:
                filterExpression = "";
                break;
        }

        filterTextField.setText(filterExpression);
        updateStatusWithAnimation("🔍 Quick filter applied: " + selectedFilter);
    }

    private void initializeCharts() {
        System.out.println("NetProtectorMainController: Initializing real-time charts...");

        // Initialize Packet Rate Chart
        if (packetRateChart != null) {
            packetRateSeries = new XYChart.Series<>();
            packetRateSeries.setName("Packets/sec");
            packetRateChart.getData().add(packetRateSeries);
            packetRateChart.setCreateSymbols(false);
            packetRateChart.setAnimated(false);
            packetRateChart.setLegendVisible(false);

            if (packetRateYAxis != null) {
                packetRateYAxis.setLabel("Packets per Second");
                packetRateYAxis.setAutoRanging(true);
            }

            if (packetRateXAxis != null) {
                packetRateXAxis.setLabel("Time");
            }
        }

        // Initialize Alert Trend Chart
        if (alertTrendChart != null) {
            alertTrendSeries = new XYChart.Series<>();
            alertTrendSeries.setName("Alerts");
            alertTrendChart.getData().add(alertTrendSeries);
            alertTrendChart.setAnimated(false);
            alertTrendChart.setLegendVisible(false);

            if (alertTrendYAxis != null) {
                alertTrendYAxis.setLabel("Alert Count");
                alertTrendYAxis.setAutoRanging(true);
            }

            if (alertTrendXAxis != null) {
                alertTrendXAxis.setLabel("Time");
            }
        }

        // Initialize Protocol Distribution Chart
        if (protocolDistributionChart != null) {
            protocolDistributionChart.setTitle("Network Protocols");
            protocolDistributionChart.setLegendVisible(true);
        }

        System.out.println("NetProtectorMainController: Real-time charts initialized.");
    }

    private void updateStatusWithAnimation(String message) {
        Platform.runLater(() -> {
            if (statusLabel != null) {
                statusLabel.setText(message);
                FadeTransition fadeIn = new FadeTransition(Duration.millis(500), statusLabel);
                fadeIn.setFromValue(0.3);
                fadeIn.setToValue(1.0);
                fadeIn.play();
            }
        });
    }

    private void initializeCoreControllers() {
        System.out.println("NetProtectorMainController: Initializing core controllers...");
        try {
            packetController = new PacketCaptureController();
            detectionController = new DetectionController();
            dbManager = new DatabaseManager();
            reportService = new ReportService(dbManager);
            System.out.println("NetProtectorMainController: Core controllers initialized successfully.");
        } catch (Exception e) {
            System.err.println("NetProtectorMainController: Error initializing core controllers: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void initializeUIComponents() {
        System.out.println("NetProtectorMainController: Initializing enhanced UI components...");

        // Initialize alert data
        alertData = FXCollections.observableArrayList();
        if (alertTableView != null) {
            alertTableView.setItems(alertData);
            setupTableColumns();
            setupTableStyling();
        }

        // Set initial button states
        setupInitialButtonStates();

        System.out.println("NetProtectorMainController: Enhanced UI components initialized.");
    }

    private void setupTableColumns() {
        if (alertTimeColumn != null) {
            alertTimeColumn.setCellValueFactory(cellData -> new javafx.beans.property.SimpleStringProperty(
                    cellData.getValue().getTimestamp().format(DateTimeFormatter.ofPattern("HH:mm:ss"))));
        }

        if (alertTitleColumn != null) {
            alertTitleColumn.setCellValueFactory(new PropertyValueFactory<>("title"));
        }

        if (alertSeverityColumn != null) {
            alertSeverityColumn.setCellValueFactory(new PropertyValueFactory<>("severity"));
            // Enhanced severity column with styling
            alertSeverityColumn.setCellFactory(column -> new TableCell<Alert, String>() {
                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setText(null);
                        setStyle("");
                        setEffect(null);
                    } else {
                        setText(item);
                        setStyle(getSeverityStyle(item));

                        // Add subtle drop shadow effect
                        DropShadow dropShadow = new DropShadow();
                        dropShadow.setColor(Color.rgb(0, 0, 0, 0.3));
                        dropShadow.setOffsetX(1);
                        dropShadow.setOffsetY(1);
                        dropShadow.setRadius(2);
                        setEffect(dropShadow);
                    }
                }
            });
        }

        if (alertSourceColumn != null) {
            alertSourceColumn.setCellValueFactory(new PropertyValueFactory<>("sourceIp"));
        }

        if (alertDestColumn != null) {
            alertDestColumn.setCellValueFactory(new PropertyValueFactory<>("destinationIp"));
        }

        if (alertProtocolColumn != null) {
            alertProtocolColumn.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        }

        if (alertPortColumn != null) {
            alertPortColumn.setCellValueFactory(new PropertyValueFactory<>("port"));
        }

        if (alertDescColumn != null) {
            alertDescColumn.setCellValueFactory(new PropertyValueFactory<>("description"));
        }
    }

    private void setupTableStyling() {
        if (alertTableView != null) {
            // Enhanced row styling
            alertTableView.setRowFactory(tv -> {
                TableRow<Alert> row = new TableRow<>();
                row.itemProperty().addListener((obs, oldAlert, newAlert) -> {
                    if (newAlert != null) {
                        String severity = newAlert.getSeverity();
                        String rowStyle = getRowStyle(severity);
                        row.setStyle(rowStyle);
                    } else {
                        row.setStyle("");
                    }
                });
                return row;
            });
        }
    }

    private void setupInitialButtonStates() {
        if (stopCaptureButton != null)
            stopCaptureButton.setDisable(true);
        if (stopDetectionButton != null)
            stopDetectionButton.setDisable(true);
        if (startDetectionButton != null)
            startDetectionButton.setDisable(true);
    }

    private String getSeverityStyle(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return "-fx-background-color: linear-gradient(to right, #dc3545, #c82333); " +
                        "-fx-text-fill: white; -fx-font-weight: bold; -fx-background-radius: 15; " +
                        "-fx-padding: 5 10 5 10; -fx-alignment: center;";
            case "HIGH":
                return "-fx-background-color: linear-gradient(to right, #fd7e14, #e8590c); " +
                        "-fx-text-fill: white; -fx-font-weight: bold; -fx-background-radius: 15; " +
                        "-fx-padding: 5 10 5 10; -fx-alignment: center;";
            case "MEDIUM":
                return "-fx-background-color: linear-gradient(to right, #ffc107, #e0a800); " +
                        "-fx-text-fill: #212529; -fx-font-weight: bold; -fx-background-radius: 15; " +
                        "-fx-padding: 5 10 5 10; -fx-alignment: center;";
            case "LOW":
                return "-fx-background-color: linear-gradient(to right, #28a745, #1e7e34); " +
                        "-fx-text-fill: white; -fx-font-weight: bold; -fx-background-radius: 15; " +
                        "-fx-padding: 5 10 5 10; -fx-alignment: center;";
            default:
                return "-fx-background-color: #6c757d; -fx-text-fill: white; " +
                        "-fx-background-radius: 15; -fx-padding: 5 10 5 10; -fx-alignment: center;";
        }
    }

    private String getRowStyle(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return "-fx-background-color: rgba(220, 53, 69, 0.1);";
            case "HIGH":
                return "-fx-background-color: rgba(253, 126, 20, 0.1);";
            case "MEDIUM":
                return "-fx-background-color: rgba(255, 193, 7, 0.1);";
            case "LOW":
                return "-fx-background-color: rgba(40, 167, 69, 0.1);";
            default:
                return "";
        }
    }

    private void startStatusUpdates() {
        statusUpdateService = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "StatusUpdateThread");
            t.setDaemon(true);
            return t;
        });

        statusUpdateService.scheduleAtFixedRate(this::updateStatusDisplay, 0, 1, TimeUnit.SECONDS);
        System.out.println("NetProtectorMainController: Enhanced status updates started.");
    }

    private void updateStatusDisplay() {
        Platform.runLater(() -> {
            // Update timestamp
            if (timestampLabel != null) {
                timestampLabel
                        .setText(LocalDateTime.now().format(DateTimeFormatter.ofPattern("🕒 yyyy-MM-dd HH:mm:ss")));
            }

            // Update packet controller stats
            if (packetController != null) {
                if (packetCountLabel != null) {
                    packetCountLabel.setText(String.format("%,d", packetController.getPacketCount()));
                }

                if (captureStatusLabel != null) {
                    String captureStatus = packetController.isCapturing() ? "🟢 Capturing" : "🔴 Stopped";
                    captureStatusLabel.setText(captureStatus);
                    captureStatusLabel
                            .setStyle(packetController.isCapturing() ? "-fx-text-fill: #28a745; -fx-font-weight: bold;"
                                    : "-fx-text-fill: #dc3545; -fx-font-weight: bold;");
                }

                // Update charts with new data
                updateCharts();
            }

            // Update detection controller stats
            if (detectionController != null) {
                DetectionModel model = detectionController.getDetectionModel();
                if (model != null) {
                    if (alertCountLabel != null) {
                        alertCountLabel.setText(String.format("%,d", model.getAlertCount()));
                    }

                    if (ruleCountLabel != null) {
                        ruleCountLabel.setText(String.format("%,d", model.getRuleCount()));
                    }

                    if (detectionStatusLabel != null) {
                        String detectionStatus = model.isRunning() ? "🟢 Detecting" : "🔴 Stopped";
                        detectionStatusLabel.setText(detectionStatus);
                        detectionStatusLabel
                                .setStyle(model.isRunning() ? "-fx-text-fill: #28a745; -fx-font-weight: bold;"
                                        : "-fx-text-fill: #dc3545; -fx-font-weight: bold;");
                    }

                    updateAlertsTable(model.getAlerts());
                }
            }

            double systemPerformance = calculateSystemPerformance();
            String performanceText = getPerformanceText(systemPerformance);
            updatePerformanceBar(systemPerformance, performanceText);

            updateSidebarStatus();
        });
    }

    private void updateCharts() {
        // Only update charts if packet capture is running
        if (packetController == null || !packetController.isCapturing()) {
            return; // Don't update charts when not capturing, but keep existing data
        }

        String currentTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));

        // Update packet rate chart
        if (packetRateSeries != null) {
            int currentPacketCount = packetController.getPacketCount();
            int packetRate = Math.max(0, currentPacketCount - lastPacketCount);
            lastPacketCount = currentPacketCount;

            packetRateHistory.offer(packetRate);
            if (packetRateHistory.size() > 30) { // Keep last 30 data points
                packetRateHistory.poll();
            }

            packetRateSeries.getData().add(new XYChart.Data<>(currentTime, packetRate));
            if (packetRateSeries.getData().size() > 30) {
                packetRateSeries.getData().remove(0);
            }
        }

        // Update alert trend chart - only if detection is also running
        if (detectionController != null && detectionController.isDetectionRunning() && alertTrendSeries != null) {
            DetectionModel model = detectionController.getDetectionModel();
            if (model != null) {
                int currentAlertCount = model.getAlertCount();
                int newAlerts = Math.max(0, currentAlertCount - lastAlertCount);
                lastAlertCount = currentAlertCount;

                alertHistory.offer(newAlerts);
                if (alertHistory.size() > 60) { // Keep last 60 minutes
                    alertHistory.poll();
                }

                alertTrendSeries.getData().add(new XYChart.Data<>(currentTime, newAlerts));
                if (alertTrendSeries.getData().size() > 60) {
                    alertTrendSeries.getData().remove(0);
                }

                // Update protocol distribution
                updateProtocolDistribution();
            }
        }
    }

    private void updateProtocolDistribution() {
        if (protocolDistributionChart == null)
            return;

        // This is a simplified example - you might want to get actual protocol data
        // from your packet capture
        protocolDistributionChart.getData().clear();

        // Example data - replace with actual protocol counts from your system
        Map<String, Integer> protocols = new HashMap<>();
        protocols.put("TCP", protocolCounts.getOrDefault("TCP", 0) + (int) (Math.random() * 10));
        protocols.put("UDP", protocolCounts.getOrDefault("UDP", 0) + (int) (Math.random() * 5));
        protocols.put("ICMP", protocolCounts.getOrDefault("ICMP", 0) + (int) (Math.random() * 2));
        protocols.put("Other", protocolCounts.getOrDefault("Other", 0) + (int) (Math.random() * 3));

        for (Map.Entry<String, Integer> entry : protocols.entrySet()) {
            if (entry.getValue() > 0) {
                PieChart.Data data = new PieChart.Data(entry.getKey() + " (" + entry.getValue() + ")",
                        entry.getValue());
                protocolDistributionChart.getData().add(data);
            }
            protocolCounts.put(entry.getKey(), entry.getValue());
        }
    }

    private void setupTooltips() {
        // Enhanced tooltips with helpful information
        if (refreshButton != null) {
            refreshButton.setTooltip(new Tooltip("Refresh the list of available network interfaces"));
        }
        if (startCaptureButton != null) {
            startCaptureButton.setTooltip(new Tooltip("Begin capturing network packets on the selected interface"));
        }
        if (stopCaptureButton != null) {
            stopCaptureButton.setTooltip(new Tooltip("Stop the current packet capture session"));
        }
        if (startDetectionButton != null) {
            startDetectionButton.setTooltip(new Tooltip("Start the threat detection engine"));
        }
        if (stopDetectionButton != null) {
            stopDetectionButton.setTooltip(new Tooltip("Stop the threat detection engine"));
        }
        if (clearAlertsButton != null) {
            clearAlertsButton.setTooltip(new Tooltip("Clear all alerts from the current view"));
        }
        if (exportAlertsButton != null) {
            exportAlertsButton.setTooltip(new Tooltip("Export current alerts to CSV file"));
        }
        if (generatePdfReportButton != null) {
            generatePdfReportButton.setTooltip(new Tooltip("Generate comprehensive PDF report"));
        }
        if (generateCsvReportButton != null) {
            generateCsvReportButton.setTooltip(new Tooltip("Generate comprehensive CSV report"));
        }
        if (filterTextField != null) {
            filterTextField.setTooltip(new Tooltip("Enter custom BPF filter or use quick filters above"));
        }
        if (quickFilterComboBox != null) {
            quickFilterComboBox.setTooltip(new Tooltip("Select from predefined common network filters"));
        }
        if (applyQuickFilterButton != null) {
            applyQuickFilterButton
                    .setTooltip(new Tooltip("Apply the selected quick filter to the custom filter field"));
        }
    }

    private void updateAlertsTable(List<Alert> currentAlerts) {
        if (alertData != null && !alertData.equals(currentAlerts)) {
            alertData.setAll(currentAlerts);
            if (alertTableView != null && !alertData.isEmpty()) {
                alertTableView.sort();

                // Add subtle animation for new alerts
                FadeTransition fadeIn = new FadeTransition(Duration.millis(300), alertTableView);
                fadeIn.setFromValue(0.8);
                fadeIn.setToValue(1.0);
                fadeIn.play();
            }
        }
    }

    private void updatePerformanceIndicator() {
        if (performanceBar == null || performanceLabel == null)
            return;

        int currentPacketCount = (packetController != null) ? packetController.getPacketCount() : 0;
        double load = Math.min(1.0, (double) currentPacketCount / 10000.0);

        Platform.runLater(() -> {
            performanceBar.setProgress(load);

            String performanceText;

            // Clear existing performance style classes
            performanceBar.getStyleClass().removeAll(
                    "performance-bar-excellent",
                    "performance-bar-good",
                    "performance-bar-average",
                    "performance-bar-poor");

            if (load < 0.3) {
                performanceText = "📊 Performance: Optimal";
                performanceBar.getStyleClass().add("performance-bar-excellent");
            } else if (load < 0.7) {
                performanceText = "📊 Performance: Moderate";
                performanceBar.getStyleClass().add("performance-bar-average");
            } else {
                performanceText = "📊 Performance: High Load";
                performanceBar.getStyleClass().add("performance-bar-poor");
            }

            performanceLabel.setText(performanceText);
        });
    }

    /**
     * Update performance bar with custom values and styling
     */
    private void updatePerformanceBar(double performanceValue, String performanceText) {
        if (performanceBar != null && performanceLabel != null) {
            Platform.runLater(() -> {
                // Update progress
                performanceBar.setProgress(Math.max(0.0, Math.min(1.0, performanceValue)));
                performanceLabel.setText(performanceText);

                // Clear existing performance style classes
                performanceBar.getStyleClass().removeAll(
                        "performance-bar-excellent",
                        "performance-bar-good",
                        "performance-bar-average",
                        "performance-bar-poor");

                // Add appropriate style class based on performance
                if (performanceValue >= 0.9) {
                    performanceBar.getStyleClass().add("performance-bar-excellent");
                } else if (performanceValue >= 0.7) {
                    performanceBar.getStyleClass().add("performance-bar-good");
                } else if (performanceValue >= 0.4) {
                    performanceBar.getStyleClass().add("performance-bar-average");
                } else {
                    performanceBar.getStyleClass().add("performance-bar-poor");
                }
            });
        }
    }

    /**
     * Calculate system performance based on multiple factors
     */
    private double calculateSystemPerformance() {
        double performance = 1.0; // Start with optimal

        // Factor in packet processing rate
        if (packetController != null) {
            int packetCount = packetController.getPacketCount();
            double packetLoad = Math.min(1.0, (double) packetCount / 10000.0);
            performance -= (packetLoad * 0.3); // Reduce performance by up to 30% based on packet load
        }

        // Factor in alert generation rate
        if (detectionController != null && detectionController.getDetectionModel() != null) {
            int alertCount = detectionController.getDetectionModel().getAlertCount();
            double alertLoad = Math.min(1.0, (double) alertCount / 100.0);
            performance -= (alertLoad * 0.2); // Reduce performance by up to 20% based on alerts
        }

        // Factor in memory usage (you can expand this with actual memory monitoring)
        Runtime runtime = Runtime.getRuntime();
        long usedMemory = runtime.totalMemory() - runtime.freeMemory();
        long maxMemory = runtime.maxMemory();
        double memoryUsage = (double) usedMemory / maxMemory;
        performance -= (memoryUsage * 0.3); // Reduce performance by up to 30% based on memory

        return Math.max(0.0, Math.min(1.0, performance));
    }

    /**
     * Get performance text based on performance value
     */
    private String getPerformanceText(double performance) {
        if (performance >= 0.9) {
            return "📊 Performance: Excellent (" + String.format("%.0f", performance * 100) + "%)";
        } else if (performance >= 0.7) {
            return "📊 Performance: Good (" + String.format("%.0f", performance * 100) + "%)";
        } else if (performance >= 0.4) {
            return "📊 Performance: Average (" + String.format("%.0f", performance * 100) + "%)";
        } else {
            return "📊 Performance: Poor (" + String.format("%.0f", performance * 100) + "%)";
        }
    }

    @FXML
    private void refreshInterfaces() {
        System.out.println("NetProtectorMainController: Refreshing network interfaces...");

        if (refreshButton != null) {
            // Add visual feedback
            refreshButton.setDisable(true);
            refreshButton.setText("🔄 Refreshing...");

            // Animate the refresh
            ScaleTransition pulse = new ScaleTransition(Duration.millis(200), refreshButton);
            pulse.setFromX(1.0);
            pulse.setFromY(1.0);
            pulse.setToX(1.1);
            pulse.setToY(1.1);
            pulse.setAutoReverse(true);
            pulse.setCycleCount(2);
            pulse.play();
        }

        // Run in background thread
        new Thread(() -> {
            try {
                Thread.sleep(500); // Simulate loading
                Platform.runLater(() -> {
                    loadNetworkInterfaces();
                    if (refreshButton != null) {
                        refreshButton.setText("🔄 Refresh");
                        refreshButton.setDisable(false);
                    }
                    updateStatusWithAnimation("🔄 Network interfaces refreshed successfully!");
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }

    private void loadNetworkInterfaces() {
        try {
            if (packetController == null) {
                System.err.println("NetProtectorMainController: PacketController is null in loadNetworkInterfaces.");
                return;
            }

            packetController.loadAvailableInterfaces();

            if (interfaceListView != null) {
                interfaceListView.setItems(packetController.getInterfaceNames());
                if (!interfaceListView.getItems().isEmpty()) {
                    interfaceListView.getSelectionModel().selectFirst();
                }
            }

            System.out.println("NetProtectorMainController: Network interfaces loaded. Count: " +
                    (interfaceListView != null ? interfaceListView.getItems().size() : 0));
        } catch (Exception e) {
            showError("Interface Load Error", "Failed to load network interfaces: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @FXML
    private void startCapture() {
        System.out.println("NetProtectorMainController: Start Capture button clicked.");

        if (interfaceListView == null) {
            showError("UI Error", "Interface list not available.");
            return;
        }

        int selectedIndex = interfaceListView.getSelectionModel().getSelectedIndex();
        if (selectedIndex == -1) {
            showError("No Interface Selected", "Please select a network interface to start capturing.");
            return;
        }

        String filter = (filterTextField != null) ? filterTextField.getText().trim() : "";
        System.out.println("NetProtectorMainController: Starting capture on interface index " + selectedIndex
                + " with filter: '" + filter + "'");

        // Enhanced button states with animations
        if (startCaptureButton != null) {
            startCaptureButton.setDisable(true);
            startCaptureButton.setText("Starting...");
        }

        new Thread(() -> {
            try {
                packetController.startCapture(selectedIndex, filter);
                Platform.runLater(() -> {
                    if (startCaptureButton != null)
                        startCaptureButton.setText("▶ Start Capture");
                    if (stopCaptureButton != null)
                        stopCaptureButton.setDisable(false);
                    if (startDetectionButton != null)
                        startDetectionButton.setDisable(false);
                    updateStatusWithAnimation(
                            "🟢 Packet capture started on " + packetController.getSelectedInterface());
                    System.out.println("NetProtectorMainController: Capture UI updated - started.");
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    if (startCaptureButton != null) {
                        startCaptureButton.setText("▶️ Start Capture");
                        startCaptureButton.setDisable(false);
                    }
                    showError("Capture Start Error", "Failed to start packet capture: " + e.getMessage());
                });
                e.printStackTrace();
            }
        }, "CaptureStartThread").start();
    }

    @FXML
    private void stopCapture() {
        System.out.println("NetProtectorMainController: Stop Capture button clicked.");
        try {
            packetController.stopCapture();
            if (detectionController != null && detectionController.getDetectionModel().isRunning()) {
                stopDetection();
            }

            // Don't clear charts - keep historical data visible
            // Charts will simply stop updating but retain their data

            if (startCaptureButton != null)
                startCaptureButton.setDisable(false);
            if (stopCaptureButton != null)
                stopCaptureButton.setDisable(true);
            if (startDetectionButton != null)
                startDetectionButton.setDisable(true);
            if (stopDetectionButton != null)
                stopDetectionButton.setDisable(true);

            updateStatusWithAnimation("🔴 Packet capture stopped - Charts preserved.");
            System.out.println("NetProtectorMainController: Capture UI updated - stopped.");
        } catch (Exception e) {
            showError("Capture Stop Error", "Error stopping packet capture: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @FXML
    private void startDetection() {
        System.out.println("NetProtectorMainController: Start Detection button clicked.");
        if (packetController == null || !packetController.isCapturing()) {
            showInfo("Capture Not Running", "Please start packet capture before starting detection.");
            return;
        }

        try {
            if (startDetectionButton != null) {
                startDetectionButton.setText("⏳ Starting...");
                startDetectionButton.setDisable(true);
            }

            startPacketBridge(packetController.getPacketQueue(), detectionController.getPacketQueue());
            detectionController.startDetection();

            if (startDetectionButton != null)
                startDetectionButton.setText("🔍 Start Detection");
            if (stopDetectionButton != null)
                stopDetectionButton.setDisable(false);

            updateStatusWithAnimation("🔍 Detection engine started and monitoring threats!");
            System.out.println("NetProtectorMainController: Detection engine started and UI updated.");
        } catch (Exception e) {
            if (startDetectionButton != null) {
                startDetectionButton.setText("🔍 Start Detection");
                startDetectionButton.setDisable(false);
            }
            showError("Detection Start Error", "Failed to start detection engine: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @FXML
    private void stopDetection() {
        System.out.println("NetProtectorMainController: Stop Detection button clicked.");
        try {
            detectionController.stopDetection();
            if (packetBridgeThread != null && packetBridgeThread.isAlive()) {
                packetBridgeThread.interrupt();
                System.out.println("NetProtectorMainController: Packet bridge thread interrupted.");
            }

            if (startDetectionButton != null) {
                startDetectionButton
                        .setDisable((packetController != null && packetController.isCapturing()) ? false : true);
            }
            if (stopDetectionButton != null)
                stopDetectionButton.setDisable(true);

            updateStatusWithAnimation("🛑 Detection engine stopped.");
            System.out.println("NetProtectorMainController: Detection engine stopped and UI updated.");
        } catch (Exception e) {
            showError("Detection Stop Error", "Error stopping detection engine: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void startPacketBridge(BlockingQueue<Packet> sourceQueue, BlockingQueue<Packet> targetQueue) {
        packetBridgeThread = new Thread(() -> {
            System.out.println("NetProtectorMainController: Packet bridge thread started.");
            while (!Thread.currentThread().isInterrupted() &&
                    packetController != null && packetController.isCapturing()) {
                try {
                    Packet packet = sourceQueue.take();
                    targetQueue.put(packet);
                } catch (InterruptedException e) {
                    System.out.println("NetProtectorMainController: Packet bridge thread interrupted.");
                    Thread.currentThread().interrupt();
                } catch (Exception e) {
                    System.err.println("NetProtectorMainController: Error in packet bridge - " + e.getMessage());
                    e.printStackTrace();
                }
            }
            System.out.println("NetProtectorMainController: Packet bridge thread stopped.");
        }, "PacketBridge-Thread");
        packetBridgeThread.setDaemon(true);
        packetBridgeThread.start();
    }

    @FXML
    private void clearSearch() {
        System.out.println("NetProtectorMainController: Clear Search button clicked.");
        if (alertSearchField != null)
            alertSearchField.clear();
        if (alertData != null)
            alertData.clear();
        updateStatusWithAnimation("Search cleared.");
        System.out.println("NetProtectorMainController: Search cleared from UI and model.");
    }

    @FXML
    private void clearAlerts() {
        System.out.println("NetProtectorMainController: Clear Alerts button clicked.");
        if (alertData != null)
            alertData.clear();
        if (detectionController != null && detectionController.getDetectionModel() != null) {
            detectionController.getDetectionModel().clearAlerts();
        }
        updateStatusWithAnimation("Alerts cleared.");
        System.out.println("NetProtectorMainController: Alerts cleared from UI and model.");
    }

    @FXML
    private void exportAlerts() {
        System.out.println("NetProtectorMainController: Export Alerts (current view) button clicked.");
        if (alertData == null || alertData.isEmpty()) {
            showInfo("No Alerts", "There are no alerts in the current view to export.");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Export Current Alerts to CSV");
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("CSV Files (*.csv)", "*.csv"));
        fileChooser.setInitialFileName("NetProtector_Current_Alerts_" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".csv");

        File file = fileChooser.showSaveDialog((alertTableView != null) ? alertTableView.getScene().getWindow() : null);
        if (file != null) {
            System.out.println("NetProtectorMainController: Exporting current alerts to: " + file.getAbsolutePath());
            exportAlertsToCSV(file, alertData);
        } else {
            System.out.println("NetProtectorMainController: Current alert export cancelled by user.");
        }
    }

    @FXML
    private void handleGeneratePdfReport() {
        System.out.println("NetProtectorMainController: Generate PDF Report button clicked.");
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save PDF Report As...");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PDF Files (*.pdf)", "*.pdf"));
        fileChooser.setInitialFileName("NetProtector_Full_Report_" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".pdf");

        File file = fileChooser.showSaveDialog((alertTableView != null) ? alertTableView.getScene().getWindow() : null);

        if (file != null) {
            try {
                reportService.exportToPDF(file.getAbsolutePath());
                showInfo("Report Generated", "PDF report has been generated and emailed (if configured).\nSaved to: "
                        + file.getAbsolutePath());
            } catch (Exception e) {
                showError("PDF Report Error", "Failed to generate PDF report: " + e.getMessage());
                e.printStackTrace();
            }
        } else {
            updateStatusWithAnimation("📄 PDF report generation cancelled.");
        }
    }

    @FXML
    private void handleGenerateCsvReport() {
        System.out.println("NetProtectorMainController: Generate CSV Report button clicked.");
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save CSV Report As...");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files (*.csv)", "*.csv"));
        fileChooser.setInitialFileName("NetProtector_Full_Report_" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".csv");

        File file = fileChooser.showSaveDialog((alertTableView != null) ? alertTableView.getScene().getWindow() : null);

        if (file != null) {
            try {
                reportService.exportToCSV(file.getAbsolutePath());
                showInfo("Report Generated", "CSV report has been generated and emailed (if configured).\nSaved to: "
                        + file.getAbsolutePath());
            } catch (Exception e) {
                showError("CSV Report Error", "Failed to generate CSV report: " + e.getMessage());
                e.printStackTrace();
            }
        } else {
            updateStatusWithAnimation("📊 CSV report generation cancelled.");
        }
    }

    private void exportAlertsToCSV(File file, ObservableList<Alert> alertsToExport) {
        try (FileWriter writer = new FileWriter(file)) {
            writer.append("ID,Timestamp,Title,Severity,Source IP,Destination IP,Protocol,Port,Description\n");

            for (Alert alert : alertsToExport) {
                writer.append(String.valueOf(alert.getId())).append(',');
                writer.append(alert.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append(',');
                writer.append("\"").append(escapeCsv(alert.getTitle())).append("\",");
                writer.append("\"").append(escapeCsv(alert.getSeverity())).append("\",");
                writer.append("\"").append(escapeCsv(alert.getSourceIp())).append("\",");
                writer.append("\"").append(escapeCsv(alert.getDestinationIp())).append("\",");
                writer.append("\"").append(escapeCsv(alert.getProtocol())).append("\",");
                writer.append(String.valueOf(alert.getPort())).append(',');
                writer.append("\"").append(escapeCsv(alert.getDescription())).append("\"\n");
            }
            writer.flush();
            updateStatusWithAnimation("📤 Alerts successfully exported to " + file.getName());
            System.out.println("NetProtectorMainController: Alerts exported successfully.");
        } catch (IOException e) {
            showError("Export Error", "Failed to export alerts to CSV: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String escapeCsv(String data) {
        if (data == null)
            return "";
        return data.replace("\"", "\"\"");
    }

    private void showError(String title, String message) {
        Platform.runLater(() -> {
            javafx.scene.control.Alert alert = new javafx.scene.control.Alert(
                    javafx.scene.control.Alert.AlertType.ERROR);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    private void showInfo(String title, String message) {
        Platform.runLater(() -> {
            javafx.scene.control.Alert alert = new javafx.scene.control.Alert(
                    javafx.scene.control.Alert.AlertType.INFORMATION);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    public void shutdown() {
        System.out.println("NetProtectorMainController: Shutdown sequence initiated...");
        this.running = false;

        if (packetBridgeThread != null && packetBridgeThread.isAlive()) {
            packetBridgeThread.interrupt();
            try {
                packetBridgeThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            System.out.println("NetProtectorMainController: Packet bridge thread stopped.");
        }

        if (packetController != null) {
            System.out.println("NetProtectorMainController: Stopping packet capture...");
            packetController.stopCapture();
        }

        if (detectionController != null) {
            System.out.println("NetProtectorMainController: Stopping detection engine...");
            detectionController.stopDetection();
        }

        // Shutdown notification controller if available
        try {
            NotificationController notificationCtrlInstance = NotificationController.getInstance();
            if (notificationCtrlInstance != null) {
                System.out
                        .println("NetProtectorMainController: Shutting down NotificationController singleton instance...");
                notificationCtrlInstance.shutdown();
            }
        } catch (Exception e) {
            System.err.println("NetProtectorMainController: Error shutting down NotificationController: " + e.getMessage());
        }

        if (statusUpdateService != null && !statusUpdateService.isShutdown()) {
            System.out.println("NetProtectorMainController: Shutting down status update service...");
            statusUpdateService.shutdown();
            try {
                if (!statusUpdateService.awaitTermination(1, TimeUnit.SECONDS)) {
                    statusUpdateService.shutdownNow();
                }
            } catch (InterruptedException e) {
                statusUpdateService.shutdownNow();
                Thread.currentThread().interrupt();
            }
            System.out.println("NetProtectorMainController: Status update service shut down.");
        }

        System.out.println("NetProtectorMainController: Shutdown sequence complete.");
    }

    private void setupAlertSearch() {
        if (alertSearchField != null && alertData != null) {
            // Create filtered list for alerts
            filteredAlerts = new FilteredList<>(alertData);

            // Bind filtered list to table view
            alertTableView.setItems(filteredAlerts);

            // Set up search functionality
            alertSearchField.textProperty().addListener((observable, oldValue, newValue) -> {
                filteredAlerts.setPredicate(alert -> {
                    // If filter text is empty, display all alerts
                    if (newValue == null || newValue.isEmpty()) {
                        return true;
                    }

                    String lowerCaseFilter = newValue.toLowerCase();

                    // Check if any alert field contains the search text
                    return alert.getTitle().toLowerCase().contains(lowerCaseFilter) ||
                            alert.getSeverity().toLowerCase().contains(lowerCaseFilter) ||
                            alert.getSourceIp().toLowerCase().contains(lowerCaseFilter) ||
                            alert.getDestinationIp().toLowerCase().contains(lowerCaseFilter) ||
                            alert.getProtocol().toLowerCase().contains(lowerCaseFilter) ||
                            alert.getDescription().toLowerCase().contains(lowerCaseFilter);
                });
            });
        }
    }

    private void setupAlertTable() {
        // Set up severity column with custom cell factory for colors
        alertSeverityColumn.setCellFactory(column -> {
            return new TableCell<Alert, String>() {
                @Override
                protected void updateItem(String severity, boolean empty) {
                    super.updateItem(severity, empty);

                    if (empty || severity == null) {
                        setText(null);
                        setStyle("");
                    } else {
                        setText(severity);

                        // Remove any existing style classes
                        getStyleClass().removeAll("severity-critical", "severity-high",
                                "severity-medium", "severity-low", "severity-info");

                        // Apply severity-specific styling
                        switch (severity.toLowerCase()) {
                            case "critical":
                                getStyleClass().add("severity-critical");
                                break;
                            case "high":
                                getStyleClass().add("severity-high");
                                break;
                            case "medium":
                                getStyleClass().add("severity-medium");
                                break;
                            case "low":
                                getStyleClass().add("severity-low");
                                break;
                            case "info":
                            default:
                                getStyleClass().add("severity-info");
                                break;
                        }
                    }
                }
            };
        });
    }

    // Add this method to set row styling based on severity
    private void setupAlertTableRowStyling() {
        alertTableView.setRowFactory(tv -> {
            TableRow<Alert> row = new TableRow<>();
            row.itemProperty().addListener((obs, oldAlert, newAlert) -> {
                if (newAlert == null) {
                    row.getStyleClass().removeAll("severity-critical", "severity-high",
                            "severity-medium", "severity-low", "severity-info");
                } else {
                    // Remove all severity classes first
                    row.getStyleClass().removeAll("severity-critical", "severity-high",
                            "severity-medium", "severity-low", "severity-info");

                    // Add appropriate severity class based on alert severity
                    String severity = newAlert.getSeverity().toLowerCase();
                    switch (severity) {
                        case "critical":
                            row.getStyleClass().add("severity-critical");
                            break;
                        case "high":
                            row.getStyleClass().add("severity-high");
                            break;
                        case "medium":
                            row.getStyleClass().add("severity-medium");
                            break;
                        case "low":
                            row.getStyleClass().add("severity-low");
                            break;
                        case "info":
                            row.getStyleClass().add("severity-info");
                            break;
                        default:
                            // Default styling, no additional class needed
                            break;
                    }
                }
            });
            return row;
        });
    }

    // Navigation methods
    @FXML
    private void showDashboard() {
        showView("dashboard");
        updateActiveNavButton(navDashboardBtn);
    }

    @FXML
    private void showMonitoring() {
        showView("monitoring");
        updateActiveNavButton(navMonitoringBtn);
    }

    @FXML
    private void showAlerts() {
        showView("alerts");
        updateActiveNavButton(navAlertsBtn);
    }

    @FXML
    private void showStatistics() {
        showView("statistics");
        updateActiveNavButton(navStatisticsBtn);
    }

    @FXML
    private void showSettings() {
        showView("settings");
        updateActiveNavButton(navSettingsBtn);
    }

    private void showView(String viewName) {
        // Hide all views
        dashboardView.setVisible(false);
        if (monitoringView != null)
            monitoringView.setVisible(false);
        if (alertsView != null)
            alertsView.setVisible(false);
        if (statisticsView != null)
            statisticsView.setVisible(false);
        if (settingsView != null)
            settingsView.setVisible(false);

        // Show selected view
        switch (viewName) {
            case "dashboard":
                dashboardView.setVisible(true);
                break;
            case "monitoring":
                if (monitoringView != null)
                    monitoringView.setVisible(true);
                break;
            case "alerts":
                if (alertsView != null)
                    alertsView.setVisible(true);
                break;
            case "statistics":
                if (statisticsView != null)
                    statisticsView.setVisible(true);
                break;
            case "settings":
                if (settingsView != null)
                    settingsView.setVisible(true);
                break;
        }
    }

    private void updateActiveNavButton(Button activeButton) {
        // Remove active class from all nav buttons
        if (navDashboardBtn != null) {
            navDashboardBtn.getStyleClass().remove("nav-btn-active");
        }
        if (navMonitoringBtn != null) {
            navMonitoringBtn.getStyleClass().remove("nav-btn-active");
        }
        if (navAlertsBtn != null) {
            navAlertsBtn.getStyleClass().remove("nav-btn-active");
        }
        if (navStatisticsBtn != null) {
            navStatisticsBtn.getStyleClass().remove("nav-btn-active");
        }
        if (navSettingsBtn != null) {
            navSettingsBtn.getStyleClass().remove("nav-btn-active");
        }

        // Add active class to selected button
        if (activeButton != null) {
            activeButton.getStyleClass().add("nav-btn-active");
        }
    }

    // Add this to your existing updateStatusDisplay method
    private void updateSidebarStatus() {
        if (captureStatusIcon != null) {
            if (packetController != null && packetController.isCapturing()) {
                captureStatusIcon.getStyleClass().clear();
                captureStatusIcon.getStyleClass().add("status-icon-running");
            } else {
                captureStatusIcon.getStyleClass().clear();
                captureStatusIcon.getStyleClass().add("status-icon-stopped");
            }
        }

        if (detectionStatusIcon != null) {
            if (detectionController != null && detectionController.getDetectionModel().isRunning()) {
                detectionStatusIcon.getStyleClass().clear();
                detectionStatusIcon.getStyleClass().add("status-icon-running");
            } else {
                detectionStatusIcon.getStyleClass().clear();
                detectionStatusIcon.getStyleClass().add("status-icon-stopped");
            }
        }

        if (alertCountBadge != null && alertData != null) {
            alertCountBadge.setText(alertData.size() + " Alerts");
        }
    }

    @FXML
    private void exitApplication() {
        System.out.println("NetProtectorMainController: Exit button clicked.");

        // Show confirmation dialog
        javafx.scene.control.Alert confirmationAlert = new javafx.scene.control.Alert(
                javafx.scene.control.Alert.AlertType.CONFIRMATION);
        confirmationAlert.setTitle("Exit NetProtector");
        confirmationAlert.setHeaderText("Are you sure you want to exit?");
        confirmationAlert.setContentText("This will stop all monitoring and detection processes.");

        // Apply dark theme styling to the alert
        DialogPane dialogPane = confirmationAlert.getDialogPane();
        dialogPane.getStylesheets().add(getClass().getResource("/css/styles.css").toExternalForm());
        dialogPane.getStyleClass().add("alert-dialog");

        // Remove window decorations/outline and make background transparent
        Stage alertStage = (Stage) confirmationAlert.getDialogPane().getScene().getWindow();
        alertStage.initStyle(javafx.stage.StageStyle.TRANSPARENT);

        // Make the scene background transparent to show the rounded dialog
        Scene scene = dialogPane.getScene();
        scene.setFill(null);

        // Apply rounded styling to the dialog pane itself
        dialogPane.setStyle(
                "-fx-background-color: rgba(30, 41, 59, 0.95);" +
                        "-fx-background-radius: 15;" +
                        "-fx-border-radius: 15;" +
                        "-fx-border-width: 2;" +
                        "-fx-border-color: rgba(99, 102, 241, 0.8);" +
                        "-fx-effect: dropshadow(gaussian, rgba(0, 0, 0, 0.5), 25, 0, 0, 10);");

        Optional<ButtonType> result = confirmationAlert.showAndWait();

        if (result.isPresent() && result.get() == ButtonType.OK) {
            // Perform cleanup
            shutdown();

            // Exit the application
            Platform.exit();
            System.exit(0);
        }
    }
}
