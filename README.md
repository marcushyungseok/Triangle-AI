# Triangle AI

## 📌 Overview

**Triangle AI** is a **distributed machine learning framework for file-based malware detection**.

It analyzes various file formats including **PDF, MS Office, JavaScript, HTML, LNK, and SWF** to extract structural features and classifies files as **benign** or **malicious** using both static analysis and machine learning (TensorFlow).

### 📁 Supported Formats & Detection Scope

| File Type | Extensions | Key Analysis Features |
|:---|:---|:---|
| **PDF** | `.pdf` | JS engine, embedded PE, stream de-obfuscation, structure integrity analysis |
| **MS Office** | `.docx, .docm, .xlsx, .xlsm` | VBA macro threat detection (MacroRaptor), external links, and obfuscation analysis |
| **Scripts** | `.js, .vbs, .ps1` | `eval`, `unescape`, `PowerShell/CMD` execution patterns, and de-obfuscation |
| **Web** | `.html, .htm` | Malicious script tags, ActiveX objects, phishing/XSS pattern analysis |
| **Windows Link** | `.lnk` | Payload download and execution detection via PowerShell/CMD |
| **Flash** | `.swf` | ActionScript API call pattern analysis and YARA-based threat detection |

> [!IMPORTANT]
> The system is designed with a **Master-Slave Cluster** architecture, not a single server. It leverages XMLRPC-based distributed processing to parse and train large volumes of files in parallel.

---

## 🏗️ System Architecture

```mermaid
graph TB
    subgraph "User / External"
        USER["User<br/>(REST API / Postman)"]
        GOOGLE["Google CSE<br/>(Custom Search Engine)"]
    end

    subgraph "learner (Core Modules)"
        MASTER["Master Node<br/>(master.py)"]
        WEB["Flask REST API<br/>(web_restful.py)"]
        CTRL["Master Controller<br/>(master_controller.py)"]
    end

    subgraph "learner_collector"
        COLLECTOR["File Collector<br/>(controller.py)"]
        GSE["Google Search<br/>(google_search.py)"]
    end

    subgraph "learner_parser"
        PDF_PARSER["PDF Parser<br/>(pdf/main.py)"]
        SWF_PARSER["SWF Parser<br/>(swf/main.py)"]
        DOCKER_BUILD["Docker Builder<br/>(dockerbuild.py)"]
    end

    subgraph "learner_model"
        FNN["FNN Model<br/>(fnn.py - TensorFlow)"]
        SCALING["Num Scaling<br/>(num_scaling.py)"]
    end

    subgraph "Slave Nodes"
        SLAVE1["Slave 1<br/>(slave.py)"]
        SLAVE2["Slave 2<br/>(slave.py)"]
    end

    subgraph "Data Storage"
        RDB["MariaDB<br/>(file_info, learner, dataset, etc.)"]
        NOSQL["MongoDB<br/>(datasets, learner_results)"]
        NFS["NFS<br/>(Source file storage)"]
        DOCKER_REG["Docker<br/>(Parser Images)"]
    end

    USER -->|HTTP REST| WEB
    WEB --> MASTER
    MASTER --> CTRL
    CTRL -->|XMLRPC| SLAVE1
    CTRL -->|XMLRPC| SLAVE2
    SLAVE1 -->|XMLRPC Result| CTRL
    SLAVE2 -->|XMLRPC Result| CTRL

    COLLECTOR --> GSE
    GSE --> GOOGLE
    COLLECTOR -->|Upload Collected Files| WEB

    SLAVE1 --> DOCKER_REG
    SLAVE1 --> NOSQL
    SLAVE1 --> NFS

    MASTER --> RDB
    MASTER --> NFS
```

---

## 📦 Core Modules

### 1. `learner` — Framework Backbone
The central module managing orchestration and distributed task allocation.

| File | Role |
|------|------|
| `starter.py` | Entry point. Launches Master/Slave via multiprocessing. |
| `cluster/master.py` | **Master Interface** — Dataset management, algorithm control, training & prediction. |
| `cluster/master_controller.py` | **Cluster Controller** — Task splitting, Slave allocation, XMLRPC management. |
| `cluster/slave.py` | **Slave Node** — Executes file parsing inside Docker and TF training/prediction. |
| `ui/web_restful.py` | Flask-RESTful based **HTTP API** (Port 8000). |
| `db/rdb_schemas.py` | 12-table RDB schema definitions. |

### 2. `learner_collector` — File Crawler
Uses **Google Custom Search Engine API** to automatically collect files (primarily PDF) from the internet.

### 3. `learner_model` — ML Intelligence
Implements a **Feedforward Neural Network (FNN)** based on **TensorFlow**. Supports dynamic algorithm loading and batch training.

### 4. `learner_parser` — Feature Extractor
Deeply inspects file formats to extract features for machine learning.
- **PDF Parser**: Regex-based parsing, stream decoding, JS extraction.
- **SWF Parser**: Tag analysis, ActionScript extraction, YARA scan.

---

## 🔌 REST API Endpoints

The system operates a Flask-RESTful server on port **8000**.

| Endpoint | Method | Description |
|------|--------|------|
| `/files` | POST | Upload files (Save to NFS + metadata to RDB) |
| `/dataset/info` | PATCH | **Start Dataset Parsing** (Distributed task) |
| `/classification/learners/<name>` | PATCH | **Start Training** |
| `/classification/learners/<name>/predict` | POST | **Predict File Risk** (Benign/Malicious) |

---

## 🐳 Kubernetes Deployment Guide

Triangle AI provides a scalable analysis engine and a visualization dashboard on Kubernetes.

![Triangle AI Dashboard](assets/triangle-ai-dashboard.png)

### Architecture

```mermaid
graph TB
    subgraph "Kubernetes/Minikube"
        DASH["Dashboard (Node.js/Chart.js)<br/>Port 3000"]
        API["Multi-Format API (Python/Flask)<br/>Port 5000"]
        DASH_SVC["dashboard-service<br/>(NodePort 30090)"]
    end
    USER -->|Upload| DASH_SVC
    DASH_SVC --> DASH
    DASH -->|POST /analyze| API
```

### Installation

```bash
cd k8s-deploy
bash deploy.sh
```

---

## 🤖 AI-Powered Analysis (Ollama Integration)

Triangle AI v0.1 supports enhanced threat reporting using **Local LLMs via Ollama**. This feature provides human-readable technical insights and mitigation strategies based on static analysis findings.

### 📋 Prerequisites
1.  **Ollama** installed on your host machine ([ollama.com](https://ollama.com)).
2.  One or more of the following models pulled:
    - `llama3.1:8b` (Recommended for general security analysis)
    - `mistral:7b`
    - `qwen2.5-coder:7b` (Recommended for script/code analysis)

### ⚙️ Configuration
The analyzer pod communicates with Ollama via the `host.minikube.internal` address (default for Minikube).

To change the model or URL, update the environment variables in `k8s/pdf-analyzer.yaml`:
```yaml
env:
  - name: OLLAMA_URL
    value: "http://host.minikube.internal:11434"
  - name: OLLAMA_MODEL
    value: "llama3.1:8b"
```

### 🧠 Features
- **Threat Assessment**: High-level summary of the file's potential intent.
- **Technical Impact**: Analysis of what the detected indicators (macros, JS APIs) can do to a system.
- **Actionable Mitigation**: Professional advice on how to handle the specific threat.

---

## 🚀 Cloud Native Security Hub

Triangle AI now includes a complete **Cloud Native Security Hub** designed for real-time monitoring of Kubernetes clusters. It uses a DaemonSet-based scanner to watch all host filesystem changes and resolves security events to specific K8s Namespaces and Pods using the Kubernetes API.

![Security Hub Dashboard](assets/security-hub-dashboard.png)

### Key Features
- **Real-time Node Protection**: DaemonSet scanner watches all files entering the cluster (e.g., via volume mounts or hostPath).
- **K8s Context Aware**: Automatically resolves file events to the responsible **Namespace** and **Pod**.
- **SOC Intelligence**: Grafana-inspired dashboard with live threat feeds, risk score timelines, and verdict distribution.
- **Persistent Forensics**: Browser-side persistent history with search and sortable analysis results.
- **AI Insights**: Automated security summaries for each detected threat via Ollama.

### Setup & Usage
1. **Deploy all components**:
   ```bash
   kubectl apply -f k8s-deploy/k8s/
   ```
2. **Access the Security Hub**:
   ```bash
   kubectl port-forward service/security-hub-service -n npe-learner 30091:3001
   ```
   Open `http://localhost:30091` in your browser.

---

## 🛠️ Tech Stack
- **Language**: Python 3.11
- **ML**: TensorFlow (FNN)
- **Web**: Flask, Express, Node.js
- **Database**: MariaDB, MongoDB
- **Storage**: NFS (Network File System)
- **Containerization**: Docker, Kubernetes (Minikube)
- **Communication**: XMLRPC

---

## ⚖️ License
Licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
