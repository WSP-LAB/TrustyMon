# TrustyMon
TrustyMon is a dynamic monitoring framework for detecting DOM-based XSS attacks using Trusted Types. TrustyMon operates in two phases: extraction and monitoring. In the extraction phase, TrustyMon automatically collects a set of signatures for benign JS snippets or URLs that are passed to injection sinks by crawling a given website. In the monitoring phase, TrustyMon dynamically monitors injection sinks that can potentially cause DOM-based XSS attacks and checks whether the supplied arguments are intended values by matching their signatures against the previously collected benign signatures. For more details, please refer to our [paper](https://dl.acm.org/doi/10.1145/3708821.3733889), "TrustyMon: Practical Detection of DOM-based Cross-Site Scripting Attacks Using Trusted Types", which appeared in ASIA CCS 2025.

## Setup
- Install Python dependencies:
  ```bash
  pip install -r requirements.txt
  ```

- Configure server IP in `client/trusty-types.js`:
  ```js
  const COLLECT_URL = "http://[ip]:21100/collect"
  const REPORT_URL  = "http://[ip]:21100/report"
  ```

- Add a CSP header to the target application:
  ```
  Content-Security-Policy-Report-Only: require-trusted-types-for 'script';
  ```

- Load the required libraries into the target application:
  - Extraction phase
    ```html
    <script src="http://[ip]:21100/js/packed.js"></script>
    <script src="http://[ip]:21100/collector.js"></script>
    ```

  - Monitoring phase
    ```html
    <script src="http://[ip]:21100/js/packed.js"></script>
    <script src="http://[ip]:21100/monitor.js"></script>
    ```

## Usage
- Initialize the database:
  ```bash
  python server.py initdb
  ```

- Run the server:
  ```bash
  python server.py
  ```

- Launch the target application with the configured CSP and injected scripts.

## Web Interface
TrustyMon provides a simple web interface for reviewing reports and managing signatures:
- View collected benign signatures: http://[ip]:21100/view/whitelists
- View detected attack reports: http://[ip]:21100/view/reports
  - If a report is a false positive, it can be added to the benign signature set.
