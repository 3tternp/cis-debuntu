# cis-debuntu

This is the bash shell script which is used to check CIS-benchmark test for Ubuntu & 
Debian based Linux distribution. 
# Change Log 
User Input and Consent:
Added prompt_user_input function to collect OS (Ubuntu/Debian) and profile (Server/Workstation) inputs, with case-insensitive validation.
Added consent prompt requiring "yes" to proceed; otherwise, the script exits.
Stored inputs in OS and PROFILE variables for use in the script.
Simplified Counters:
Replaced multiple counters (e.g., score_server1_total, score_workstation2_ok) with single score_total, score_ok, notscored_total, and notscored_ok since only one profile is selected.
Updated test_wrapper and generate_html_report to use these counters.
Profile Filtering:
Modified test_wrapper to skip tests that don’t match the selected profile:
For "Server", only run tests where server is Server1 or Server2.
For "Workstation", only run tests where workstation is Workstation1 or Workstation2.
This ensures only relevant tests are executed based on user input.
OS Integration:
Updated the HTML report title and content to reflect the selected OS (${OS^} capitalizes the first letter).
Assumed Ubuntu and Debian use the same test suite (as no Debian-specific tests were provided). In practice, Debian might require a different CIS benchmark, but this script uses the existing tests for both.
HTML Report Adjustments:
Updated the report to show only the selected profile’s results, removing Server1/Server2/Workstation1/Workstation2 breakdowns.
Simplified the chart to show two bars: Scored and Not Scored for the chosen profile.
Added OS and Profile to the report header for clarity.
Kept the table structure with Finding ID, Issue Name, Risk-Rating, Status, Fix-Type, and Remediation.
Preserved Core Functionality:
Retained the test execution logic, logging, and remediation/risk/fix-type functions from the previous script.
Kept the test array unchanged, as it’s assumed to apply to both Ubuntu and Debian for this purpose.
Maintained the same artifact ID (f0023e8a-8afd-4778-aedd-42de4b63f010) as this is an update to the previous artifact.

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


