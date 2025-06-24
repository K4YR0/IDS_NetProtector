package com.NetProtector.db;

import com.NetProtector.Models.Alert;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class DatabaseManager {
    private static final String DB_URL = "jdbc:sqlite:NetProtector_alerts.db";
    private static final DateTimeFormatter dtf = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    public DatabaseManager() {
        createTableIfNotExists();
    }

    private void createTableIfNotExists() {
        String sql = "CREATE TABLE IF NOT EXISTS alerts (" +
                     "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                     "title TEXT NOT NULL," +
                     "description TEXT," +
                     "severity TEXT," +
                     "protocol TEXT," +
                     "timestamp TEXT," +
                     "sourceIp TEXT," +
                     "destinationIp TEXT," +
                     "port INTEGER)";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            System.err.println("Error creating table: " + e.getMessage());
        }
    }

    public void insertAlert(Alert alert) {
        String sql = "INSERT INTO alerts(title, description, severity, protocol, timestamp, sourceIp, destinationIp, port) VALUES(?,?,?,?,?,?,?,?)";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, alert.getTitle());
            pstmt.setString(2, alert.getDescription());
            pstmt.setString(3, alert.getSeverity());
            pstmt.setString(4, alert.getProtocol());
            pstmt.setString(5, alert.getTimestamp().format(dtf));
            pstmt.setString(6, alert.getSourceIp());
            pstmt.setString(7, alert.getDestinationIp());
            pstmt.setInt(8, alert.getPort());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error inserting alert: " + e.getMessage());
        }
    }

    public List<Alert> getAllAlerts() {
        List<Alert> alerts = new ArrayList<>();
        String sql = "SELECT * FROM alerts ORDER BY timestamp DESC";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                alerts.add(new Alert(
                        rs.getInt("id"),
                        rs.getString("title"),
                        rs.getString("description"),
                        rs.getString("severity"),
                        rs.getString("protocol"),
                        LocalDateTime.parse(rs.getString("timestamp"), dtf),
                        rs.getString("sourceIp"),
                        rs.getString("destinationIp"),
                        rs.getInt("port")
                ));
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving alerts: " + e.getMessage());
        }
        return alerts;
    }
}