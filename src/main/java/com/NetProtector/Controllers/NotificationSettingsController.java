package com.NetProtector.Controllers;

import com.NetProtector.Models.Rules.Severity;
import javafx.animation.FadeTransition;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.util.Duration;

import java.net.URL;
import java.util.ResourceBundle;

public class NotificationSettingsController implements Initializable {

    // FXML Controls - Remove emailUsernameField and senderEmailInfoLabel
    @FXML private CheckBox desktopNotificationsCheckBox;
    @FXML private CheckBox emailNotificationsCheckBox;
    @FXML private TextField emailRecipientField;
    @FXML private Label emailConfigStatusLabel;
    @FXML private Button saveSettingsButton;
    @FXML private Label saveStatusLabel;
    @FXML private ComboBox<Severity> testSeverityComboBox;
    @FXML private Button sendTestNotificationButton;
    @FXML private Label notificationStatusLabel;

    private NotificationController notificationController;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        System.out.println("NotificationSettingsController: Initializing enhanced notification settings...");
        
        try {
            // Get the singleton instance of NotificationController
            notificationController = NotificationController.getInstance();
            
            if (notificationController != null) {
                notificationController.initializeNotificationManager();
                setupUIBindings();
                setupInitialValues();
                setupAnimations();
                System.out.println("NotificationSettingsController: Enhanced initialization complete.");
            } else {
                System.err.println("NotificationSettingsController: NotificationController instance is null.");
                handleInitializationError();
            }
        } catch (Exception e) {
            System.err.println("NotificationSettingsController: Error during initialization: " + e.getMessage());
            e.printStackTrace();
            handleInitializationError();
        }
    }

    private void setupUIBindings() {
        if (notificationController == null) return;

        // Bind desktop notifications checkbox
        if (desktopNotificationsCheckBox != null) {
            desktopNotificationsCheckBox.selectedProperty().bindBidirectional(
                notificationController.desktopNotificationsEnabledProperty());
            desktopNotificationsCheckBox.selectedProperty().addListener((obs, oldVal, newVal) -> {
                updateOverallStatusLabel();
                animateStatusUpdate();
            });
        }

        // Bind email notifications checkbox
        if (emailNotificationsCheckBox != null) {
            emailNotificationsCheckBox.selectedProperty().bindBidirectional(
                notificationController.emailNotificationsEnabledProperty());
            emailNotificationsCheckBox.selectedProperty().addListener((obs, oldVal, newVal) -> {
                updateEmailConfigStatus();
                updateOverallStatusLabel();
                animateStatusUpdate();
            });
        }

        // Bind email recipient field
        if (emailRecipientField != null) {
            emailRecipientField.textProperty().bindBidirectional(
                notificationController.emailRecipientProperty());
            emailRecipientField.textProperty().addListener((obs, oldVal, newVal) -> {
                updateEmailConfigStatus();
                updateOverallStatusLabel();
            });
        }

        // Remove the emailUsernameField binding code since it's no longer in the UI
    }

    private void setupInitialValues() {
        // Remove sender email info label setup since it's no longer in the UI
        
        // Setup test severity combo box
        if (testSeverityComboBox != null && notificationController != null) {
            testSeverityComboBox.setItems(notificationController.getAvailableSeverities());
            if (!notificationController.getAvailableSeverities().isEmpty()) {
                testSeverityComboBox.getSelectionModel().selectFirst();
            }
        }

        // Initial status updates
        updateOverallStatusLabel();
        updateEmailConfigStatus();
    }

    private void setupAnimations() {
        // Add hover animations to buttons
        if (saveSettingsButton != null) {
            setupButtonAnimation(saveSettingsButton);
        }
        if (sendTestNotificationButton != null) {
            setupButtonAnimation(sendTestNotificationButton);
        }
    }

    private void setupButtonAnimation(Button button) {
        button.setOnMouseEntered(e -> {
            button.setStyle(button.getStyle() + "; -fx-scale-x: 1.05; -fx-scale-y: 1.05;");
        });
        button.setOnMouseExited(e -> {
            button.setStyle(button.getStyle().replace("; -fx-scale-x: 1.05; -fx-scale-y: 1.05;", ""));
        });
    }

    private void animateStatusUpdate() {
        if (notificationStatusLabel != null) {
            FadeTransition fadeIn = new FadeTransition(Duration.millis(300), notificationStatusLabel);
            fadeIn.setFromValue(0.5);
            fadeIn.setToValue(1.0);
            fadeIn.play();
        }
    }

    private void handleInitializationError() {
        Platform.runLater(() -> {
            if (saveStatusLabel != null) {
                saveStatusLabel.setText("❌ Error: Notification system not available.");
                saveStatusLabel.setStyle("-fx-text-fill: #dc3545; -fx-font-weight: bold;");
            }
            
            if (notificationStatusLabel != null) {
                notificationStatusLabel.setText("⚠️ Notification system initialization failed. Please check system configuration.");
                notificationStatusLabel.setStyle("-fx-text-fill: #dc3545;");
            }

            // Disable controls (remove emailUsernameField from this list)
            if (saveSettingsButton != null) saveSettingsButton.setDisable(true);
            if (sendTestNotificationButton != null) sendTestNotificationButton.setDisable(true);
            if (desktopNotificationsCheckBox != null) desktopNotificationsCheckBox.setDisable(true);
            if (emailNotificationsCheckBox != null) emailNotificationsCheckBox.setDisable(true);
            if (emailRecipientField != null) emailRecipientField.setDisable(true);
        });
    }

    @FXML
    private void handleSaveSettings() {
        if (notificationController == null) {
            showStatusMessage("❌ Error: Notification system not available.", "#dc3545");
            return;
        }

        showStatusMessage("💾 Saving settings...", "#007bff");
        
        try {
            notificationController.saveSettings();
            Platform.runLater(() -> {
                showStatusMessage("✅ Settings saved successfully!", "#28a745");
                updateOverallStatusLabel();
                updateEmailConfigStatus();
                animateStatusUpdate();
                
                // Clear status message after 3 seconds
                new Thread(() -> {
                    try {
                        Thread.sleep(3000);
                        Platform.runLater(() -> clearStatusMessage());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }).start();
            });
        } catch (Exception e) {
            System.err.println("NotificationSettingsController: Error saving settings: " + e.getMessage());
            showStatusMessage("❌ Error saving settings: " + e.getMessage(), "#dc3545");
        }
    }

    @FXML
    private void handleSendTestNotification() {
        if (notificationController == null) {
            showStatusMessage("❌ Error: Notification system not available.", "#dc3545");
            return;
        }

        Severity selectedSeverity = null;
        if (testSeverityComboBox != null) {
            selectedSeverity = testSeverityComboBox.getSelectionModel().getSelectedItem();
        }

        if (selectedSeverity != null) {
            try {
                notificationController.sendTestNotification(selectedSeverity);
                showStatusMessage("Test notification sent for " + selectedSeverity + " severity!", "#28a745");
                
                // Clear status message after 3 seconds
                new Thread(() -> {
                    try {
                        Thread.sleep(3000);
                        Platform.runLater(() -> clearStatusMessage());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }).start();
            } catch (Exception e) {
                System.err.println("NotificationSettingsController: Error sending test notification: " + e.getMessage());
                showStatusMessage("❌ Error sending test notification: " + e.getMessage(), "#dc3545");
            }
        } else {
            showStatusMessage("⚠️ Please select a severity for the test notification.", "#ffc107");
        }
    }

    private void updateEmailConfigStatus() {
        if (emailConfigStatusLabel == null || emailNotificationsCheckBox == null) {
            System.err.println("NotificationSettingsController: Required UI components are null for email config status update.");
            return;
        }

        Platform.runLater(() -> {
            if (emailNotificationsCheckBox.isSelected()) {
                if (isEmailConfigurationValid()) {
                    emailConfigStatusLabel.setText("✅ Email configuration is valid and ready.");
                    emailConfigStatusLabel.setStyle("-fx-text-fill: #28a745; -fx-font-weight: bold;");
                } else {
                    emailConfigStatusLabel.setText("⚠️ Email configuration is incomplete. Please check your recipient email address.");
                    emailConfigStatusLabel.setStyle("-fx-text-fill: #dc3545; -fx-font-weight: bold;");
                }
            } else {
                emailConfigStatusLabel.setText("📧 Email notifications are disabled.");
                emailConfigStatusLabel.setStyle("-fx-text-fill: #6c757d;");
            }
        });
    }

    private boolean isEmailConfigurationValid() {
        String recipient = (emailRecipientField != null) ? emailRecipientField.getText() : "";
        boolean isEmailNotificationsEnabled = (emailNotificationsCheckBox != null) && emailNotificationsCheckBox.isSelected();

        // Only check recipient email since sender email is now hidden
        return isEmailNotificationsEnabled &&
               recipient != null && !recipient.trim().isEmpty() && recipient.contains("@");
    }

    private void updateOverallStatusLabel() {
        if (notificationController == null || notificationStatusLabel == null) {
            System.err.println("NotificationSettingsController: Required components are null for overall status update.");
            return;
        }

        Platform.runLater(() -> {
            StringBuilder status = new StringBuilder();
            
            // Check desktop notifications
            if (desktopNotificationsCheckBox != null && desktopNotificationsCheckBox.isSelected()) {
                status.append("🖥️ Desktop notifications enabled. ");
            }
            
            // Check email notifications
            if (emailNotificationsCheckBox != null && emailNotificationsCheckBox.isSelected()) {
                if (isEmailConfigurationValid()) {
                    status.append("📧 Email notifications configured and enabled.");
                } else {
                    status.append("⚠️ Email notifications enabled but configuration needs attention.");
                }
            }
            
            // If no notifications are enabled
            if (status.length() == 0) {
                status.append("🔕 No notifications are currently enabled. Enable at least one notification method to receive alerts.");
            }
            
            notificationStatusLabel.setText(status.toString());
            
            // Style based on configuration status
            if (status.toString().contains("⚠️")) {
                notificationStatusLabel.setStyle("-fx-text-fill: #dc3545;");
            } else if (status.toString().contains("🔕")) {
                notificationStatusLabel.setStyle("-fx-text-fill: #ffc107;");
            } else {
                notificationStatusLabel.setStyle("-fx-text-fill: #28a745;");
            }
        });
    }

    private void showStatusMessage(String message, String color) {
        Platform.runLater(() -> {
            if (saveStatusLabel != null) {
                saveStatusLabel.setText(message);
                saveStatusLabel.setStyle("-fx-text-fill: " + color + "; -fx-font-weight: bold;");
                
                // Add fade-in animation
                FadeTransition fadeIn = new FadeTransition(Duration.millis(300), saveStatusLabel);
                fadeIn.setFromValue(0.0);
                fadeIn.setToValue(1.0);
                fadeIn.play();
            }
        });
    }

    private void clearStatusMessage() {
        Platform.runLater(() -> {
            if (saveStatusLabel != null) {
                // Add fade-out animation
                FadeTransition fadeOut = new FadeTransition(Duration.millis(300), saveStatusLabel);
                fadeOut.setFromValue(1.0);
                fadeOut.setToValue(0.0);
                fadeOut.setOnFinished(e -> saveStatusLabel.setText(""));
                fadeOut.play();
            }
        });
    }

    // Public method to refresh status from external calls
    public void refreshStatus() {
        updateOverallStatusLabel();
        updateEmailConfigStatus();
        animateStatusUpdate();
    }

    // Cleanup method
    public void shutdown() {
        System.out.println("NotificationSettingsController: Performing cleanup...");
        // Any cleanup operations can be added here
    }
}
