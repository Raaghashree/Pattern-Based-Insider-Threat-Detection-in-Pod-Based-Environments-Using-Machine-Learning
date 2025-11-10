# Pattern-Based-Insider-Threat-Detection-in-Pod-Based-Environments-Using-Machine-Learning

# 1.1 Overview of the Proposed Tool
The proposed insider threat detection tool leverages a hybrid approach combining Machine Learning (ML) and rule-based logic to identify suspicious activities within DevSecOps and pod-based environments. It is specifically designed to address the complexity of tracking and analyzing dynamic logs in microservice architectures, where traditional manual monitoring is ineffective.

# 1.2 Detection Methodology
The core detection engine utilizes a combination of the following models and techniques:

🔸 Tree-Based ML Models:

- XGBoost: Detects complex anomaly patterns using gradient boosting. 

- Isolation Forest: Identifies outliers by isolating data points in a feature space.

🔸 Neural Networks:

- Autoencoders: Learn compressed representations of normal behavior and flag deviations as anomalies.

🔸 Rule-Based Logic:

- Applies predefined security rules to capture known threat signatures, policy violations, or suspicious activity indicators.

These approaches work in parallel to ensure both novel and known insider threat patterns are effectively detected.

# 1.3 Simulated Dashboard
A Streamlit-based dashboard has been implemented to visually demonstrate the workings of the detection approach. Although it does not support live log ingestion or scanning, the dashboard performs the following simulation tasks:

  - Loads a pre-collected log dataset representing real-world events (Login activity, file access, network behavior, etc.).

  - Allows the user to trigger the detection process manually.

  - Displays a results interface with:
 
  - Alert counts (total anomalies detected).

  - Affected user identifiers.

  - Brief descriptions of the detected anomalies.

# 1.4 Purpose and Significance
This tool is designed as a proof-of-concept to illustrate how pattern-based ML detection can be integrated into DevSecOps workflows.

It emphasizes the proactive nature of detecting insider threats early by analyzing system behavior patterns.

While currently implemented as a simulation, the framework paves the way for future deployment into real-time detection systems integrated within CI/CD pipelines or security orchestration platforms. 

# 1.5 Future Scope and Impact

As insider threats continue to evolve within cloud-native and containerized infrastructures, this project lays foundational work for scalable, automated defense mechanisms. Future enhancements may include live integration with Kubernetes audit logs, RBAC policy analysis, and incorporation into SIEM/SOAR platforms for real-time response. By bridging the gap between observability and intelligent threat detection, this tool exemplifies how ML can strengthen zero-trust security in DevSecOps pipelines.

