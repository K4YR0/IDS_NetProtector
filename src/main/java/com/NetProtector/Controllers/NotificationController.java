package com.NetProtector.Controllers;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import com.NetProtector.Models.Alert;
import com.NetProtector.Models.Rules.Severity;
import com.NetProtector.Services.EmailNotificationService;
import com.NetProtector.Services.NotificationManager;
import com.NetProtector.Services.NotificationServiceFactory;
import com.NetProtector.config.NotificationConfig;

import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

public class NotificationController {
    
    private static final String CONFIG_FILE_PATH = "notification.properties";
    private static NotificationController instance;
    
    private NotificationManager notificationManager;
    private NotificationConfig config;
    private Properties properties;
    
    private final BooleanProperty desktopNotificationsEnabled = new SimpleBooleanProperty(false);
    private final BooleanProperty emailNotificationsEnabled = new SimpleBooleanProperty(false);
    private final StringProperty emailRecipient = new SimpleStringProperty("");
    private final StringProperty emailUsername = new SimpleStringProperty("");
    
    private final ObservableList<Severity> availableSeverities = FXCollections.observableArrayList(Severity.values());
    
    private NotificationController() {
        loadConfiguration();
        initializeProperties();
    }
    
    public static synchronized NotificationController getInstance() {
        if (instance == null) {
            instance = new NotificationController();
        }
        return instance;
    }

    public void initializeNotificationManager() {
        try {
            config = new NotificationConfig();
            
            NotificationServiceFactory factory = new NotificationServiceFactory(config) {
                @Override
                public NotificationManager createNotificationManager() {
                    NotificationManager manager = new NotificationManager();
                    manager.setGlobalRateLimit(config.getGlobalRateLimit());
                    
                    for (Severity severity : Severity.values()) {
                        manager.setSeverityEnabled(severity, config.isSeverityEnabled(severity));
                    }
                    
                    if (config.isDesktopEnabled()) {
                        manager.addService(createDesktopNotificationService());
                    }
                    
                    if (config.isEmailEnabled()) {
                        manager.addService(createEmailNotificationServiceWithCurrentValues());
                    }
                    
                    return manager;
                }
            };
            
            notificationManager = factory.createNotificationManager();
            notificationManager.start();
        } catch (Exception e) {
            // Fail silently
        }
    }
    
    private void loadConfiguration() {
        properties = new Properties();
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(CONFIG_FILE_PATH)) {
            if (input != null) {
                properties.load(input);
            }
        } catch (IOException e) {
            // Fail silently
        }
    }
    
    private void initializeProperties() {
        desktopNotificationsEnabled.set(Boolean.parseBoolean(properties.getProperty("notification.desktop.enabled", "true")));
        emailNotificationsEnabled.set(Boolean.parseBoolean(properties.getProperty("notification.email.enabled", "false")));
        emailRecipient.set(properties.getProperty("notification.email.recipient", ""));
        emailUsername.set(properties.getProperty("notification.email.username", ""));
    }
    
    public void sendTestNotification(Severity severity) {
        if (notificationManager == null) {
            initializeNotificationManager();
        }
        
        if (notificationManager != null) {
            Alert testAlert = new Alert(
                999, // ID
                "Test NetProtector",
                "This is a test notification. Notifications are working correctly!",
                severity.name(), // Severity
                "TEST", // Protocol
                java.time.LocalDateTime.now(), // Timestamp
                "127.0.0.1", // Source IP
                "127.0.0.1", // Destination IP
                0 // Port
            );
            notificationManager.processAlert(testAlert);
        }
    }
    
    public void saveSettings() {
        try {
            properties.setProperty("notification.desktop.enabled", String.valueOf(desktopNotificationsEnabled.get()));
            properties.setProperty("notification.email.enabled", String.valueOf(emailNotificationsEnabled.get()));
            properties.setProperty("notification.email.recipient", emailRecipient.get());
            properties.setProperty("notification.email.username", emailUsername.get());
            properties.setProperty("notification.console.enabled", "false");
            
            String configPath = "src/main/resources/" + CONFIG_FILE_PATH;
            try (FileOutputStream output = new FileOutputStream(configPath)) {
                properties.store(output, "NetProtector Notification Configuration");
            }
            
            if (notificationManager != null) {
                notificationManager.stop();
            }
            initializeNotificationManager();
        } catch (IOException e) {
            // Fail silently
        }
    }
    
    private EmailNotificationService createEmailNotificationServiceWithCurrentValues() {
        return new EmailNotificationService(
            emailUsername.get(),
            emailRecipient.get(),
            config.getEmailHost(),
            config.getEmailPort(),
            config.getEmailUseTls(),
            config.getGlobalRateLimit(),
            createTimestampMap(),
            config.getOauthClientId(),
            config.getOauthClientSecret(),
            config.getOauthRefreshToken()
        );
    }
    
    private Map<Severity, Instant> createTimestampMap() {
        Map<Severity, Instant> timestamps = new HashMap<>();
        for (Severity severity : Severity.values()) {
            timestamps.put(severity, null);
        }
        return timestamps;
    }

    public BooleanProperty desktopNotificationsEnabledProperty() { return desktopNotificationsEnabled; }
    public BooleanProperty emailNotificationsEnabledProperty() { return emailNotificationsEnabled; }
    public StringProperty emailRecipientProperty() { return emailRecipient; }
    public StringProperty emailUsernameProperty() { return emailUsername; }
    public ObservableList<Severity> getAvailableSeverities() { return availableSeverities; }

    public void shutdown() {
        if (notificationManager != null) {
            notificationManager.stop();
        }
    }
}