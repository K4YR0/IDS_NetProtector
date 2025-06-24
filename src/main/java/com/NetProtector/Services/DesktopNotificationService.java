package com.NetProtector.Services;

import com.NetProtector.Models.Alert;
import com.NetProtector.Models.Rules.Severity;

// AWT imports - requires java.desktop module
import java.awt.*;
// import java.awt.TrayIcon;
// import java.awt.SystemTray;
import java.awt.TrayIcon.MessageType;
import java.awt.image.BufferedImage;
import java.time.Instant;
import java.util.Map;

public class DesktopNotificationService implements NotificationService {
    
    private final long rateLimitSeconds;
    private final Map<Severity, Instant> lastSentTimestamps;
    private final String applicationName;
    private TrayIcon trayIcon;
    private boolean isRunning = false;

    public DesktopNotificationService(long rateLimitSeconds, Map<Severity, Instant> lastSentTimestamps, String applicationName) {
        this.rateLimitSeconds = rateLimitSeconds;
        this.lastSentTimestamps = lastSentTimestamps;
        this.applicationName = applicationName;
    }

    @Override
    public void start() {
        if (!SystemTray.isSupported()) {
            return;
        }

        try {
            SystemTray tray = SystemTray.getSystemTray();
            
            Image image = Toolkit.getDefaultToolkit().createImage(getClass().getResource("/icons/shield.png"));
            if (image == null) {
                image = createFallbackImage();
            }
            
            trayIcon = new TrayIcon(image, applicationName);
            trayIcon.setImageAutoSize(true);
            tray.add(trayIcon);
            
            isRunning = true;
        } catch (AWTException | SecurityException e) {
            // Fail silently
        }
    }

    @Override
    public void notify(Alert alert) {
        if (!isRunning || alert == null || trayIcon == null) return;
        
        Instant now = Instant.now();
        Severity severity = Severity.valueOf(alert.getSeverity());
        Instant lastSent = lastSentTimestamps.get(severity);
        
        if (lastSent != null && now.minusSeconds(rateLimitSeconds).isBefore(lastSent)) {
            return;
        }
        lastSentTimestamps.put(severity, now);

        MessageType type;
        switch (severity) {
            case LOW:
                type = MessageType.INFO;
                break;
            case MEDIUM:
                type = MessageType.WARNING;
                break;
            case HIGH:
            case CRITICAL:
                type = MessageType.ERROR;
                break;
            default:
                type = MessageType.NONE;
        }
        
        try {
            trayIcon.displayMessage(
                String.format("%s - %s Alert", applicationName, severity),
                alert.getTitle() + ": " + alert.getDescription(),
                type
            );
        } catch (Exception e) {
            // Fail silently
        }
    }

    @Override
    public void stop() {
        if (isRunning && trayIcon != null) {
            SystemTray tray = SystemTray.getSystemTray();
            tray.remove(trayIcon);
            isRunning = false;
        }
    }
    
    private Image createFallbackImage() {
        BufferedImage image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setColor(Color.RED);
        g.fillRect(0, 0, 16, 16);
        g.dispose();
        return image;
    }
}