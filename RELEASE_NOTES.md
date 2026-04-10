# Release Notes - v0.1 (Initial Version)

## 🚀 Overview
**Triangle AI** v0.1 is the initial public release of our distributed file-based malware detection framework. It provides end-to-end capabilities from file collection and structural parsing to machine learning-based classification and professional visualization.

## ✨ Key Features
- **Multi-Format Analysis**: Supports deep static inspection for PDF, MS Office, JavaScript, HTML, LNK, and SWF files.
- **Advanced Backend Engine**: Integrated specialized tools like `oletools` for macro detection and custom regex-based scanners.
- **Premium Dashboard**: Grafana-inspired dark theme UI featuring real-time risk scoring, radar charts, and detailed threat reports.
- **Universal K8s Deployment**: One-click deployment script (`deploy.sh`) supporting both local Minikube and remote cloud clusters.
- **Distributed Architecture**: Master-Slave cluster design using XMLRPC for high-performance parallel file parsing and training.
- **Machine Learning Integration**: TensorFlow-based FNN model for intelligent "Benign vs Malicious" classification.

## 📦 Deployment
- Version: `v0.1.0`
- GitHub Repository: [Triangle-AI](https://github.com/marcushyungseok/Triangle-AI)
- License: Apache 2.0
