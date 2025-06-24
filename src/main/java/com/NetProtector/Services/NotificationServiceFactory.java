package com.NetProtector.Services;

import com.NetProtector.Models.Rules.Severity;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import com.NetProtector.config.NotificationConfig;


public class NotificationServiceFactory {
    private final NotificationConfig config;
    
    public NotificationServiceFactory(NotificationConfig config) {
        this.config = config;
    }
    
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
            manager.addService(createEmailNotificationService());
        }
        
        return manager;
    }
    
    private Map<Severity, Instant> createTimestampMap() {
        Map<Severity, Instant> map = new ConcurrentHashMap<>();
        for (Severity severity : Severity.values()) {
            map.put(severity, Instant.EPOCH);
        }
        return map;
    }
    
    public DesktopNotificationService createDesktopNotificationService() {
        return new DesktopNotificationService(
            config.getGlobalRateLimit(),
            createTimestampMap(),
            config.getApplicationName()
        );
    }
    
    public EmailNotificationService createEmailNotificationService() {
        return new EmailNotificationService(
            config.getEmailUsername(),
            config.getEmailRecipient(),
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
}