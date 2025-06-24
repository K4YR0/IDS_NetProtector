package com.NetProtector.Services;

import com.google.auth.oauth2.UserCredentials;
import com.NetProtector.Models.Alert;
import com.NetProtector.Models.Rules.Severity;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Properties;

import jakarta.mail.Multipart;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMultipart;
import java.io.File;

public class EmailNotificationService implements NotificationService {
    private final String username;
    private final String recipient;
    private final String smtpHost;
    private final int smtpPort;
    private final String clientId;
    private final String clientSecret;
    private final String refreshToken;
    private final long rateLimitSeconds;
    private final Map<Severity, Instant> lastSentTimestamps;
    private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public EmailNotificationService(String username, String recipient, String smtpHost, int smtpPort, boolean useTls,
                                    long rateLimitSeconds, Map<Severity, Instant> lastSentTimestamps,
                                    String clientId, String clientSecret, String refreshToken) {
        this.username = username;
        this.recipient = recipient;
        this.smtpHost = smtpHost;
        this.smtpPort = smtpPort;
        this.rateLimitSeconds = rateLimitSeconds;
        this.lastSentTimestamps = lastSentTimestamps;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.refreshToken = refreshToken;
    }

    @Override
    public void notify(Alert alert) {
        Instant now = Instant.now();
        Severity severity = Severity.valueOf(alert.getSeverity());
        if (lastSentTimestamps.get(severity) != null &&
            now.minusSeconds(rateLimitSeconds).isBefore(lastSentTimestamps.get(severity))) {
            return;
        }

        Properties props = new Properties();
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", String.valueOf(smtpPort));
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.starttls.required", "true");
        props.put("mail.smtp.auth.mechanisms", "XOAUTH2");

        Session session = Session.getInstance(props);
        Transport transport = null;

        try {
            UserCredentials credentials = UserCredentials.newBuilder()
                .setClientId(clientId)
                .setClientSecret(clientSecret)
                .setRefreshToken(refreshToken)
                .build();
            credentials.refresh();
            String accessToken = credentials.getAccessToken().getTokenValue();

            if (accessToken == null || accessToken.trim().isEmpty()) {
                throw new IllegalStateException("Failed to obtain a valid access token.");
            }

            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
            String subject = String.format("[NetProtector %s Alert] %s", severity, alert.getTitle());
            message.setSubject(subject);

            String body = String.format(
                "NetProtector Security Alert\n" +
                "========================\n\n" +
                "Time: %s\n" +
                "Severity: %s\n" +
                "Title: %s\n" +
                "Description: %s\n",
                formatter.format(alert.getTimestamp()), severity, alert.getTitle(), alert.getDescription()
            );
            message.setText(body);

            transport = session.getTransport("smtp");
            transport.connect(smtpHost, username, accessToken);
            transport.sendMessage(message, message.getAllRecipients());

            lastSentTimestamps.put(severity, now);
        } catch (Exception e) {
            // Fail silently
        } finally {
            if (transport != null && transport.isConnected()) {
                try {
                    transport.close();
                } catch (MessagingException e) {
                    // Fail silently
                }
            }
        }
    }

    public void sendReport(String filePath) {
        if (username == null || username.trim().isEmpty() || recipient == null || recipient.trim().isEmpty()) {
            return; // Don't send if sender or recipient is not configured
        }

        Properties props = new Properties();
        // ... same properties setup as in notify() method
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", String.valueOf(smtpPort));
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.starttls.required", "true");
        props.put("mail.smtp.auth.mechanisms", "XOAUTH2");

        Session session = Session.getInstance(props);
        Transport transport = null;

        try {
            UserCredentials credentials = UserCredentials.newBuilder()
                .setClientId(clientId)
                .setClientSecret(clientSecret)
                .setRefreshToken(refreshToken)
                .build();
            credentials.refresh();
            String accessToken = credentials.getAccessToken().getTokenValue();

            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
            message.setSubject("NetProtector Security Report");

            // Create the message part
            MimeBodyPart messageBodyPart = new MimeBodyPart();
            messageBodyPart.setText("Please find the attached security report from NetProtector.");

            // Create the attachment part
            MimeBodyPart attachmentPart = new MimeBodyPart();
            attachmentPart.attachFile(new File(filePath));

            // Create a multipart message
            Multipart multipart = new MimeMultipart();
            multipart.addBodyPart(messageBodyPart);
            multipart.addBodyPart(attachmentPart);

            message.setContent(multipart);
            
            transport = session.getTransport("smtp");
            transport.connect(smtpHost, username, accessToken);
            transport.sendMessage(message, message.getAllRecipients());
            
        } catch (Exception e) {
            // Fail silently
        } finally {
            if (transport != null && transport.isConnected()) {
                try {
                    transport.close();
                } catch (MessagingException e) {
                    // Fail silently
                }
            }
        }
    }
}