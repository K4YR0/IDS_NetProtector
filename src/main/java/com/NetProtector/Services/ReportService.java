package com.NetProtector.Services;

import com.NetProtector.db.DatabaseManager;
import com.NetProtector.Models.Alert;
import com.NetProtector.config.NotificationConfig;

import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import com.opencsv.CSVWriter;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class ReportService {
    private final DatabaseManager dbManager;
    private final EmailNotificationService emailService;

    public ReportService(DatabaseManager dbManager) {
        this.dbManager = dbManager;
        NotificationConfig config = new NotificationConfig();
        NotificationServiceFactory factory = new NotificationServiceFactory(config);
        this.emailService = factory.createEmailNotificationService();
    }

    public void exportToCSV(String filePath) throws Exception {
        List<Alert> alerts = dbManager.getAllAlerts();
        try (CSVWriter writer = new CSVWriter(new FileWriter(filePath))) {
            writer.writeNext(new String[]{"ID", "Timestamp", "Title", "Severity", "Source IP", "Destination IP", "Protocol", "Port"});
            for (Alert alert : alerts) {
                writer.writeNext(new String[]{
                        String.valueOf(alert.getId()),
                        alert.getTimestamp().toString(),
                        alert.getTitle(),
                        alert.getSeverity(),
                        alert.getSourceIp(),
                        alert.getDestinationIp(),
                        alert.getProtocol(),
                        String.valueOf(alert.getPort())
                });
            }
        }
        emailService.sendReport(filePath);
    }

    public void exportToPDF(String filePath) throws Exception {
        List<Alert> alerts = dbManager.getAllAlerts();
        Document document = new Document();
        try {
            PdfWriter.getInstance(document, new FileOutputStream(filePath));
            document.open();
            document.add(new Paragraph("NetProtector Intrusion Detection Report"));
            document.add(new Paragraph(" ")); // Empty line

            PdfPTable table = new PdfPTable(7);
            table.setWidthPercentage(100);
            table.addCell("Timestamp");
            table.addCell("Title");
            table.addCell("Severity");
            table.addCell("Source IP");
            table.addCell("Dest IP");
            table.addCell("Protocol");
            table.addCell("Port");

            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

            for (Alert alert : alerts) {
                table.addCell(alert.getTimestamp().format(formatter));
                table.addCell(alert.getTitle());
                table.addCell(alert.getSeverity());
                table.addCell(alert.getSourceIp());
                table.addCell(alert.getDestinationIp());
                table.addCell(alert.getProtocol());
                table.addCell(String.valueOf(alert.getPort()));
            }
            document.add(table);
        } finally {
            document.close();
        }
        emailService.sendReport(filePath);
    }
}