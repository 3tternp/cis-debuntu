# cis-debuntu

This is the bash shell script which is used to check CIS-benchmark test for Ubuntu & 
Debian based Linux distribution. 
# Change Log 
🔐 User Input and Consent
Added prompt_user_input function to collect:

Operating System (OS) input (Ubuntu or Debian) — case-insensitive validation.

Profile selection input (Server or Workstation) — validated for correct role type.

Consent Prompt Introduced:

Before executing the audit, the script prompts the user: "Do you want to continue? (yes/no)"

If the user does not type yes, the script exits safely.

Inputs are stored in variables OS and PROFILE for use in logic and reporting.

📊 Simplified Counters
Removed the use of multiple scoped counters like score_server1_total, score_workstation2_ok, etc.

Introduced unified counters:

score_total, score_ok

notscored_total, notscored_ok

Used within test_wrapper and generate_html_report to summarize results consistently for the chosen profile only.

🧠 Profile Filtering Logic
Updated test_wrapper to run only relevant tests based on selected profile:

For Server, executes only tests where server == Server1 or Server2

For Workstation, executes only tests where workstation == Workstation1 or Workstation2

This ensures that the user sees results tailored to their environment, avoiding unrelated noise.

🖥️ OS Integration
Introduced the OS variable from user input to reflect the operating system (Ubuntu/Debian).

The HTML report’s title and body now reference ${OS^} (capitalized for clarity).

Test suite is assumed common to both Ubuntu and Debian for now.

Note: Debian-specific benchmarks may differ. The script currently uses a unified suite.

📈 HTML Report Enhancements
Report header now includes:

Selected OS (Ubuntu or Debian)

Selected Profile (Server or Workstation)

Visual simplification:

Removed column breakdowns for Server1, Server2, Workstation1, Workstation2.

Chart simplified to reflect:

Scored results

Not Scored results

Table structure preserved:

Finding ID

Description

Risk-Rating

Status (Pass/Fail/Skip)

Fix-Type

Remediation Guidance

⚙️ Core Logic and Functionality Preserved
Maintains:

The existing test execution loop

Logging via cis_audit.log

Remediation, risk rating, and fix-type processing per test

Test array untouched:

Applies equally to both Ubuntu and Debian in current implementation

Structured for easy future extension

🆔 Artifact Reference
Artifact ID: f0023e8a-8afd-4778-aedd-42de4b63f010

This update enhances the usability and maintainability of the original script while keeping its fundamental structure.

# usage 
```
git clone https://github.com/3tternp/cis-debuntu
cd cis-debuntu/
chmod +x cisdebuntucheck.sh
./cisdebuntucheck.sh
```
<img width="936" height="676" alt="image" src="https://github.com/user-attachments/assets/40913ff9-6e6a-4472-b0ae-f99aeac1906e" />
<img width="881" height="682" alt="image" src="https://github.com/user-attachments/assets/df5c10d9-2c8e-40cf-8b3d-ccf42b06b44e" />




# output
<img width="899" height="922" alt="image" src="https://github.com/user-attachments/assets/c411198a-f4b6-412c-b1a1-ad8910a1c525" />


