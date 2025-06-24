package com.NetProtector.Services;

import com.NetProtector.Models.Alert;
import com.NetProtector.Models.Rules.Severity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.time.Instant;

public class NotificationManager {
    private final List<NotificationService> services = new ArrayList<>();
    private final Map<Severity, Instant> lastSentTimestamps = new HashMap<>();
    private final Map<Severity, Boolean> enabledSeverities = new HashMap<>();
    private long globalRateLimitSeconds = 30;

    public NotificationManager() {
        for (Severity severity : Severity.values()) {
            enabledSeverities.put(severity, true);
            lastSentTimestamps.put(severity, Instant.EPOCH);
        }
    }

    public void addService(NotificationService service) {
        if (service != null) {
            services.add(service);
            service.start();
        }
    }

    public void removeService(NotificationService service) {
        if (service != null && services.contains(service)) {
            service.stop();
            services.remove(service);
        }
    }

    public void setSeverityEnabled(Severity severity, boolean enabled) {
        enabledSeverities.put(severity, enabled);
    }

    public void setGlobalRateLimit(long seconds) {
        if (seconds >= 0) {
            this.globalRateLimitSeconds = seconds;
        }
    }

    public void processAlert(Alert alert) {
        if (alert == null) return;

        Severity severity = Severity.valueOf(alert.getSeverity());

        if (!enabledSeverities.getOrDefault(severity, true)) {
            return;
        }
        
        Instant now = Instant.now();
        Instant lastSent = lastSentTimestamps.get(severity);
        if (lastSent != null && now.minusSeconds(globalRateLimitSeconds).isBefore(lastSent)) {
            return;
        }
        
        lastSentTimestamps.put(severity, now);
        
        for (NotificationService service : services) {
            try {
                service.notify(alert);
            } catch (Exception e) {
                // Fail silently
            }
        }
    }

    public void start() {
        for (NotificationService service : services) {
            service.start();
        }
    }

    public void stop() {
        for (NotificationService service : services) {
            service.stop();
        }
    }
}