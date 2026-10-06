# 🛡️️ End-to-End Cyber Threat Intelligence (CTI) Pipeline

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-7.0-DC382D?logo=redis&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Machine_Learning-Scikit_Learn-F7931E?logo=scikit-learn&logoColor=white)
![ChromaDB](https://img.shields.io/badge/Vector_DB-ChromaDB-FF4F8B)

An automated, microservices-based Data Engineering and MLOps pipeline designed to ingest, classify, and visualize real-time Open Source Intelligence (OSINT) cyber threats.

## 📌 Project Overview
This project simulates a modern Security Operations Center (SOC) backend. It automates the collection of raw cyber threat news, utilizes a hybrid **Decision Tree + RAG (Retrieval-Augmented Generation)** approach to dynamically score threat severity, and generates executive-ready PDF dashboards. 

### Key Features:
* **Real-time OSINT Ingestion:** Automated scraping of major cybersecurity RSS feeds, parsed and queued via Redis.
* **ML-Driven Classification:** A scikit-learn Decision Tree model trained on baseline threat data, enhanced by ChromaDB (semantic search) to prevent hallucination and adjust confidence scores.
* **Dynamic Risk Scoring:** An isolated Data Mart (`tableau_mart`) continuously calculates risk priority based on base severity, AI confidence drift, and 24-hour threat velocity.
* **Infrastructure as Code:** Fully containerized architecture using Docker Compose.
* **Automated BI Reporting:** Scheduled generation of multi-page PDF Executive Dashboards (using Pandas, Seaborn, and ReportLab).

---

## 🏗️ System Architecture

The pipeline consists of 6 isolated Docker containers communicating via a virtual network:

1. **`scraper_app`**: Fetches live RSS data and pushes raw JSON payloads to a Redis queue.
2. **`redis_db`**: In-memory message broker handling the `threat_queue`.
3. **`redis_consumer` (ML Engine)**: Pops events from Redis, queries **ChromaDB** for semantic context, predicts severity via **Decision Tree**, and writes to PostgreSQL.
4. **`postgres_db`**: The core data warehouse containing OLTP (`threat_logs`) and OLAP (`tableau_mart`) tables.
5. **`tableau_engine`**: Transforms raw logs into calculated metrics (Dynamic Risk Score, Threat Velocity).
6. **`reporter_app`**: Queries the Data Mart and builds analytical charts, exporting them to an Executive PDF report.

---

## 🚀 Getting Started

### Prerequisites
* Docker and Docker Compose installed.
* Python 3.10+ (for local development only).
* A valid `.env` file (see configuration below).

### 1. Configuration
Create a `.env` file in the root directory with the following variables:
```env
POSTGRES_USER=your_user
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=cyber_threat_db
GEMINI_API_KEY=your_api_key_here # Required only if regenerating baseline data