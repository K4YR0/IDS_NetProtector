package com.NetProtector.Models;
import java.time.LocalDateTime;
import javafx.beans.property.*;

public class Alert {
    private final IntegerProperty id = new SimpleIntegerProperty();
    private final StringProperty title = new SimpleStringProperty();
    private final StringProperty description = new SimpleStringProperty();
    private final StringProperty severity = new SimpleStringProperty();
    private final StringProperty protocol = new SimpleStringProperty();
    private final ObjectProperty<LocalDateTime> timestamp = new SimpleObjectProperty<>();
    private final StringProperty sourceIp = new SimpleStringProperty();
    private final StringProperty destinationIp = new SimpleStringProperty();
    private final IntegerProperty port = new SimpleIntegerProperty();
    
    public Alert(int id, String title, String description, String severity, String protocol, 
                 LocalDateTime timestamp, String sourceIp, String destinationIp, int port) {
        this.id.set(id);
        this.title.set(title);
        this.description.set(description);
        this.severity.set(severity);
        this.protocol.set(protocol);
        this.timestamp.set(timestamp);
        this.sourceIp.set(sourceIp);
        this.destinationIp.set(destinationIp);
        this.port.set(port);
    }
    
    // Property getters
    public IntegerProperty idProperty() { return id; }
    public StringProperty titleProperty() { return title; }
    public StringProperty descriptionProperty() { return description; }
    public StringProperty severityProperty() { return severity; }
    public StringProperty protocolProperty() { return protocol; }
    public ObjectProperty<LocalDateTime> timestampProperty() { return timestamp; }
    public StringProperty sourceIpProperty() { return sourceIp; }
    public StringProperty destinationIpProperty() { return destinationIp; }
    public IntegerProperty portProperty() { return port; }
    
    // Regular getters
    public int getId() { return id.get(); }
    public String getTitle() { return title.get(); }
    public String getDescription() { return description.get(); }
    public String getSeverity() { return severity.get(); }
    public String getProtocol() { return protocol.get(); }
    public LocalDateTime getTimestamp() { return timestamp.get(); }
    public String getSourceIp() { return sourceIp.get(); }
    public String getDestinationIp() { return destinationIp.get(); }
    public int getPort() { return port.get(); }
}