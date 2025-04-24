Here’s the list of **required tools** that need to be installed and configured to run the **Recon Scanner Tool**:

### 1. **Subfinder**
   - **Purpose**: Used for passive subdomain enumeration.
   - **Installation**:
     ```bash
     go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
     ```

### 2. **Assetfinder**
   - **Purpose**: Another tool for discovering subdomains.
   - **Installation**:
     ```bash
     go install github.com/assetfinder/assetfinder@latest
     ```

### 3. **Dirsearch**
   - **Purpose**: Used for brute-forcing directories on a target domain or IP.
   - **Installation**:
     ```bash
     git clone https://github.com/maurosoria/dirsearch.git
     cd dirsearch
     ```

### 4. **Python 3.x**
   - **Purpose**: Required to run the recon script.
   - **Installation**:
     - Install Python 3 if it's not installed already.
     - You can check the version using:
       ```bash
       python3 --version
       ```

### 5. **Python Libraries**:
   - **Requests** (for HTTP requests).
   - **Argparse** (for parsing command-line arguments).
   - **Installation**:
     ```bash
     pip install requests argparse
     ```

### Summary of Installation Steps:
1. **Install Python 3**.
2. **Install required Python libraries**:
   ```bash
   pip install requests argparse
   ```
3. **Install external tools**:
   - Subfinder: `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
   - Assetfinder: `go install github.com/assetfinder/assetfinder@latest`
   - Dirsearch: `git clone https://github.com/maurosoria/dirsearch.git`

This is the minimum set of tools needed for the Recon Scanner to work effectively.
