<div align="center">
<pre>
███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
</pre>
</div>

<p align="center">
<em><code>Real-time Intrusion Detection System (IDS) built with Java & JavaFX for comprehensive network threat monitoring.</code></em>
</p>

<p align="center">
<img src="https://img.shields.io/badge/Java-17-orange" alt="Java">
<img src="https://img.shields.io/badge/JavaFX-21-blue" alt="JavaFX">
<img src="https://img.shields.io/badge/Maven-3.8+-green" alt="Maven">
<img src="https://img.shields.io/badge/License-MIT-yellow" alt="license">
</p>

-----

## 🔗 Table of Contents

- [📍 Overview](#-overview)
- [👾 Features](#-features)
- [📁 Project Structure](#-project-structure)
    - [📂 Project Index](#-project-index)
- [🚀 Getting Started](#-getting-started)
    - [☑️ Prerequisites](#-prerequisites)
    - [⚙️ Installation](#-installation)
    - [🤖 Usage](#-usage)
- [🔰 Contributing](#-contributing)
- [🎗 License](#-license)

-----

## 📍 Overview

**NetProtector** is a desktop-based Intrusion Detection System (IDS) developed in Java and JavaFX that captures, analyzes, and alerts on real-time network threats. With 15+ built-in detection rules, an interactive dashboard, and persistent historical data logging, it’s designed to assist security analysts and network administrators in monitoring suspicious activities and generating actionable insights.

-----

## 👾 Features

### 🧠 Core Capabilities
- 🔴 **Live Packet Sniffing** via `pcap4j`
- ⚙️ **Multithreaded Detection Engine** running over 15 security rules
- 📊 **Interactive JavaFX Dashboard** with real-time graphs and logs
- 🚨 **Alerts System**: Desktop pop-ups and email notifications
- 🕓 **Historical Tracking**: Alerts saved in a local SQLite database

### 🛡️ Detection Rules
- DDoS Attack Detection  
- Brute Force Monitoring  
- SQL Injection  
- DNS Tunneling  
- Malicious IP Tracking  
- Port Scanning  
- Suspicious Traffic Heuristics  
- And more...

### 📤 Reporting Tools
- PDF Report Generation (`iTextPDF`)
- CSV Export (`OpenCSV`)
- Real-time Email Notifications (`Jakarta Mail`)
- Detailed Logs & Desktop Alerts

-----

## 📁 Project Structure

```bash
IDS_NetProtector/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/NetProtector/
│   │   │       ├── controllers/     # UI Controllers
│   │   │       ├── models/          # Data Models
│   │   │       ├── services/        # IDS Logic & Detection
│   │   │       ├── utils/           # Helper Utilities
│   │   │       └── Main.java        # Entry Point
│   │   └── resources/
│   │       ├── fxml/                # FXML UI Layouts
│   │       ├── css/                 # Stylesheets
│   │       └── images/              # Icons and Assets
├── docs/images/                     # Screenshots
├── pom.xml                          # Maven Config
└── README.md                        # This File
```

### 📂 Project Index

<details open>
<summary><b>Key Components</b></summary>

| File/Folder                          | Description                                                |
|-------------------------------------|------------------------------------------------------------|
| `Main.java`                         | Application launcher and JavaFX entry point               |
| `controllers/`                      | Handles GUI interactions                                   |
| `services/`                         | Core IDS functionality and rule engine                    |
| `utils/`                            | Email, Logging, and PDF Export Utilities                   |
| `notification.properties`           | Email settings (requires setup)                            |
| `pom.xml`                           | Maven dependencies and plugins                             |
</details>

-----

## 🚀 Getting Started

### ☑️ Prerequisites

- Java 17+
- Maven 3.8+
- Administrative privileges (for raw packet capture)
- Supported OS: Windows, macOS, or Linux
- Access to network interfaces

### ⚙️ Installation

1. **Clone the repository**
```bash
git clone https://github.com/K4YR0/IDS_NetProtector.git
cd IDS_NetProtector
```

2. **Install dependencies**
```bash
mvn clean install
```

3. **Run the application**
```bash
mvn javafx:run
# Or launch the JAR directly
java -jar target/IDS_NetProtector-1.0.jar
```

### 🤖 Usage

1. Launch the application with **administrator/root privileges**
2. Choose the appropriate **network interface**
3. Adjust detection rules in the **Settings** panel
4. Click **Start IDS** to begin monitoring
5. Watch real-time **alerts populate** the dashboard
6. Use the **Export** tab for PDF/CSV reports

-----

## 📸 Screenshots

<p align="center">
  <img src="https://raw.githubusercontent.com/K4YR0/IDS_NetProtector/main/docs/images/dashboard.png" width="75%"><br>
  <em>Main Dashboard with Live Monitoring</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/K4YR0/IDS_NetProtector/main/docs/images/alerts.png" width="75%"><br>
  <em>Alerts & Notifications Panel</em>
</p>

-----

## ⚙️ Configuration

### ✉️ Email Notifications

1. Copy the template file:
```bash
cp notification_placeholder.properties notification.properties
```

2. Update SMTP settings:
```properties
notification.email.username=your-email@gmail.com
notification.email.recipient=alerts@yourdomain.com
# Use an app-specific password if using Gmail
```

### 🔒 Detection Rules

You can fine-tune detection thresholds directly via the Settings panel in the UI or modify rule constants in `services/`.

-----

## 🔰 Contributing

1. **Fork** this repository  
2. **Create a feature branch**  
```bash
git checkout -b feature/amazing-feature
```
3. **Commit your changes**  
```bash
git commit -m 'Add amazing feature'
```
4. **Push the branch**  
```bash
git push origin feature/amazing-feature
```
5. **Open a Pull Request**

<a href="https://github.com/K4YR0/IDS_NetProtector/graphs/contributors">
<img src="https://contrib.rocks/image?repo=K4YR0/IDS_NetProtector" />
</a>

Made with ❤️ by the Open Source Community.

-----

## 🎗 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

-----

## 🔮 Future Enhancements

- [ ] Machine Learning-based Anomaly Detection
- [ ] Web-based Dashboard Interface
- [ ] Integration with Threat Intelligence Feeds
- [ ] REST API for third-party tools
- [ ] Advanced Traffic Visualizations
- [ ] Multi-node IDS Cluster Support

-----

⭐ If you found **NetProtector** helpful, please consider giving it a ⭐ on GitHub!
