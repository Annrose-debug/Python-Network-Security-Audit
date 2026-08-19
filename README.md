```
+-----------------------------------------------------------------+
|                       Python Audit Engine                       |
+-----------------------------------------------------------------+
                                 |
        +------------------------+------------------------+
        |                                                 |
        v                                                 v
+-------------------------------+       +-------------------------------+
|    Resource Telemetry Engine  |       |   Multi-Threaded Port Scanner |
|    (CPU, RAM, Disk, Netstat)  |       |   (Socket Connection & Banner)|
+-------------------------------+       +-------------------------------+
        |                                                 |
        +------------------------+------------------------+
                                 |
                                 v
+-----------------------------------------------------------------+
|                    HTML Report Generator                        |
|             (Generates audit-report.html)                       |
+-----------------------------------------------------------------+
```

## 🛠 Script Components & Modules

| Module / Function | Technical Implementation | Purpose |
| :--- | :--- | :--- |
| **System Telemetry** | `psutil` | Captures CPU utilization %, RAM usage, disk usage, and active network sockets. |
| **Port Scanner** | `socket`, `concurrent.futures` | Executes multi-threaded TCP connect scans across target ports (e.g., 21, 22, 80, 443, 3389, 8080). |
| **Banner Grabber** | `socket.recv()` | Retrieves service identification headers from open TCP ports for enumeration. |
| **Reporting Engine** | Python String Formatting / Jinja2 | Builds a styled standalone HTML file with severity indicators. |

---

## ⚙️ Quick Start & Usage

### Prerequisites
* Python 3.8 or higher
* Required packages:
  ```bash
  pip install psutil
