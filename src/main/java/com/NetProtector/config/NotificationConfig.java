package com.NetProtector.config;

import com.NetProtector.Models.Rules.Severity;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class NotificationConfig {
    private static final String DEFAULT_CONFIG_PATH = "notification.properties";
    private static final long DEFAULT_RATE_LIMIT = 60;
    private static final String DEFAULT_APP_NAME = "NetProtector IDS";
    private static final boolean DEFAULT_DESKTOP_ENABLED = true;
    private static final boolean DEFAULT_EMAIL_ENABLED = false;
    private static final String DEFAULT_EMAIL_HOST = "smtp.gmail.com";
    private static final int DEFAULT_EMAIL_PORT = 587;
    private static final boolean DEFAULT_EMAIL_TLS = true;
    private static final String DEFAULT_EMAIL_USERNAME = "";
    private static final String DEFAULT_EMAIL_RECIPIENT = "";
    private static final String DEFAULT_OAUTH_CLIENT_ID = "";
    private static final String DEFAULT_OAUTH_CLIENT_SECRET = "";
    private static final String DEFAULT_OAUTH_REFRESH_TOKEN = "";

    private final Properties properties = new Properties();

    public NotificationConfig() {
        loadProperties(DEFAULT_CONFIG_PATH);
    }

    public NotificationConfig(String configPath) {
        loadProperties(configPath);
    }

    private void loadProperties(String path) {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(path)) {
            if (input == null) {
                return;
            }
            properties.load(input);
        } catch (IOException ex) {
            // Fail silently
        }
    }

    public String getStringProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    public long getLongProperty(String key, long defaultValue) {
        try {
            return Long.parseLong(properties.getProperty(key));
        } catch (NumberFormatException | NullPointerException e) {
            return defaultValue;
        }
    }

    public int getIntProperty(String key, int defaultValue) {
        try {
            return Integer.parseInt(properties.getProperty(key));
        } catch (NumberFormatException | NullPointerException e) {
            return defaultValue;
        }
    }

    public boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = properties.getProperty(key);
        return (value != null) ? Boolean.parseBoolean(value) : defaultValue;
    }

    public long getGlobalRateLimit() {
        return getLongProperty("notification.rateLimit", DEFAULT_RATE_LIMIT);
    }

    public String getApplicationName() {
        return getStringProperty("notification.appName", DEFAULT_APP_NAME);
    }

    public boolean isDesktopEnabled() {
        return getBooleanProperty("notification.desktop.enabled", DEFAULT_DESKTOP_ENABLED);
    }

    public boolean isEmailEnabled() {
        return getBooleanProperty("notification.email.enabled", DEFAULT_EMAIL_ENABLED);
    }

    public String getEmailHost() {
        return getStringProperty("notification.email.host", DEFAULT_EMAIL_HOST);
    }

    public int getEmailPort() {
        return getIntProperty("notification.email.port", DEFAULT_EMAIL_PORT);
    }

    public boolean getEmailUseTls() {
        return getBooleanProperty("notification.email.tls", DEFAULT_EMAIL_TLS);
    }

    public String getEmailUsername() {
        return getStringProperty("notification.email.username", DEFAULT_EMAIL_USERNAME);
    }
    
    public String getEmailRecipient() {
        return getStringProperty("notification.email.recipient", DEFAULT_EMAIL_RECIPIENT);
    }

    public String getOauthClientId() {
        return getStringProperty("notification.email.oauth.clientId", DEFAULT_OAUTH_CLIENT_ID);
    }
    
    public String getOauthClientSecret() {
        return getStringProperty("notification.email.oauth.clientSecret", DEFAULT_OAUTH_CLIENT_SECRET);
    }
    
    public String getOauthRefreshToken() {
        return getStringProperty("notification.email.oauth.refreshToken", DEFAULT_OAUTH_REFRESH_TOKEN);
    }
    
    public boolean isSeverityEnabled(Severity severity) {
        String key = "notification.severity." + severity.name().toLowerCase() + ".enabled";
        return getBooleanProperty(key, true);
    }
}