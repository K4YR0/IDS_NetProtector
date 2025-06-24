module com.NetProtector {

    requires org.pcap4j.core;
    requires transitive javafx.base;
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.graphics;
    
    // Added for Desktop Notifications
    requires java.desktop;
    
    // Added for Email Notifications
    requires jakarta.mail;
    requires com.google.auth.oauth2;

    // DB and Reporting
    requires java.sql;
    requires itextpdf;
    requires com.opencsv;

    // Logging modules
    requires org.apache.logging.log4j;

    opens com.NetProtector to javafx.fxml;
    opens com.NetProtector.Controllers to javafx.fxml;
    opens com.NetProtector.Models to javafx.base;

    exports com.NetProtector;
    exports com.NetProtector.db;
    exports com.NetProtector.Controllers;
    exports com.NetProtector.Models;
    exports com.NetProtector.Models.Rules;
    exports com.NetProtector.Services;
}