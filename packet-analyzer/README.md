# 🔍 DPI Packet Analyzer — Java Spring Boot

Java Spring Boot port of [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer) (originally in C++).

---

## Architecture (C++ → Java mapping)

| C++ Component | Java Component | Description |
|---|---|---|
| `pcap_reader.cpp` | `PcapReader.java` | Reads PCAP binary format |
| `packet_parser.cpp` | `PacketParser.java` | Parses Ethernet/IP/TCP/UDP headers |
| `sni_extractor.cpp` | `SniExtractor.java` | Extracts SNI from TLS Client Hello |
| `types.cpp` | `AppClassifier.java` | Maps hostname → AppType |
| `rule_manager.h` | `RuleManager.java` | IP/App/Domain blocking rules |
| `dpi_mt.cpp` | `DpiEngine.java` | Multi-threaded orchestrator |
| CLI args | `DpiController.java` | REST API |

---

## How to Run

### Prerequisites
- Java 17+
- Maven 3.8+

### Build & Start
```bash
mvn clean package -DskipTests
java -jar target/packet-analyzer-1.0.0.jar
```

Server starts at: **http://localhost:8080**

---

## API Usage

### 1. Analyze a PCAP file
```bash
curl -X POST http://localhost:8080/api/dpi/analyze \
     -F "file=@your_capture.pcap"
```

### 2. Analyze with blocking rules
```bash
curl -X POST http://localhost:8080/api/dpi/analyze \
     -F "file=@capture.pcap" \
     -F "blockApps=YOUTUBE,TIKTOK" \
     -F "blockIps=192.168.1.50" \
     -F "blockDomains=facebook"
```

### 3. Manage rules separately
```bash
# Add blocked IP
curl -X POST http://localhost:8080/api/dpi/rules/ip \
     -H "Content-Type: application/json" \
     -d '{"ip": "192.168.1.50"}'

# Add blocked app
curl -X POST http://localhost:8080/api/dpi/rules/app \
     -H "Content-Type: application/json" \
     -d '{"app": "YOUTUBE"}'

# Add blocked domain keyword
curl -X POST http://localhost:8080/api/dpi/rules/domain \
     -H "Content-Type: application/json" \
     -d '{"domain": "tiktok"}'

# View current rules
curl http://localhost:8080/api/dpi/rules

# Clear all rules
curl -X DELETE http://localhost:8080/api/dpi/rules
```

### 4. Get supported app types
```bash
curl http://localhost:8080/api/dpi/apps
```

---

## Sample API Response

```json
{
  "totalPackets": 77,
  "tcpPackets": 73,
  "udpPackets": 4,
  "totalBytes": 5738,
  "forwarded": 69,
  "dropped": 8,
  "appBreakdown": {
    "HTTPS": 39,
    "UNKNOWN": 16,
    "YOUTUBE": 4,
    "DNS": 4,
    "FACEBOOK": 3
  },
  "detectedSnis": [
    "www.facebook.com",
    "www.github.com",
    "www.google.com",
    "www.youtube.com"
  ],
  "blockedFlows": [
    {
      "flow": "192.168.1.100:54321 -> 172.217.14.206:443 [TCP]",
      "reason": "APP_BLOCKED(YOUTUBE)",
      "packets": 4
    }
  ],
  "warnings": []
}
```

---

## How DPI Works (The Key Insight)

Even though HTTPS traffic is encrypted, the **TLS Client Hello** packet (the very first packet of every HTTPS connection) contains the destination hostname in **plain text** as the SNI (Server Name Indication) extension.

```
TLS Client Hello:
└── Extensions:
    └── SNI Extension (0x0000):
        └── Server Name: "www.youtube.com"  ← Visible in plain text!
```

Our engine reads this before any encryption kicks in, so we can identify and block traffic to specific applications without breaking encryption.

---

## Supported Applications

`YOUTUBE`, `GOOGLE`, `FACEBOOK`, `INSTAGRAM`, `TWITTER`, `TIKTOK`, `NETFLIX`, `AMAZON`, `GITHUB`, `TWITCH`, `WHATSAPP`, `TELEGRAM`, `REDDIT`, `LINKEDIN`, `ZOOM`, `DISCORD`

---

## Run Tests
```bash
mvn test
```
