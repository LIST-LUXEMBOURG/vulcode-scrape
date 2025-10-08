# vulcode-scrape

This project automatically collects source code with software vulnerabilityies from bitbucket, GitHub, and gitlab. The vulnerabilty information is sourced from the Common Vulnerabilities and Exposures (CVE) records in the public U.S. National Vulnerability Database (NVD). 


## ⚙️ Prerequisites

This project requires two environment variables to be set **before running the code**:

| Variable        | Description                                             |
|-----------------|---------------------------------------------------------|
| `GITHUB_USER`   | Your GitHub username.                                   |
| `GITHUB_TOKEN`  | Your GitHub Personal Access Token (PAT) with appropriate permissions. |

---

### 🧩 Setting Environment Variables

You can set environment variables in several ways depending on your operating system or workflow.

#### **Option 1: Shell Profile (Linux/macOS)**

Add the following lines to your shell configuration file (`~/.bashrc`, `~/.zshrc`, or `~/.profile`):

```bash
export GITHUB_USER=your_github_username
export GITHUB_TOKEN=your_personal_access_token
```

Then reload your shell:

```bash
source ~/.bashrc  # or ~/.zshrc
```

#### **Option 2: System/User Environment Variables (Windows)**

Set environment variables via **System Properties → Environment Variables**, or use PowerShell:

```powershell
setx GITHUB_USER "your_github_username"
setx GITHUB_TOKEN "your_personal_access_token"
```

#### **Option 3: `.env` File (Recommended for Development)**

Create a `.env` file in the **project root** with the following content:

```env
GITHUB_USER=your_github_username
GITHUB_TOKEN=your_personal_access_token
```

---

### 🚨 Security Note

> **Never** commit your `.env` file, tokens, or any credentials to version control.  
> Use a `.gitignore` file to exclude `.env` and keep your secrets secure.

Example `.gitignore` entry:

```
.env
```

---


## 🔎 Usage

Run the following command to create a vulnerability database:

```bash
python main.py \
    --database_dir <directory_path> \
    --ini_year <start_year> \
    --end_year <end_year>
```

#### 🔥 Example. The following command will collect vulnerabile code with CVEs recorded from 2021 to 2025.

```bash
python main.py --database_dir Data --ini_year 2021 --end_year 2025
```

### ✨ Relevant Projects

[CVEfixes](https://github.com/secureIT-project/CVEfixes): our project is inspired by its structure.

[NVD data feeds](https://nvd.nist.gov/vuln/data-feeds): where we get the CVE records.

[CWE](https://cwe.mitre.org/): where we obtain the CWE information




---


© 2025 - Luxembourg Institute of Science and Technology. All Rights Reserved

This software is licensed under [GPL V3.0 Licence](https://www.gnu.org/licenses/gpl-3.0.txt)
