 <h1>Splunk Searches for a SOC Analyst</h1>

 <h2>Failed Login Brute Force</h2>

 `index=windows EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 10`

<b>Detects:</b> Password spraying, Brute-force attacks
<b>Helps confirm true positive if:</b> Many failures from one IP, Multiple usernames targeted, Happens outside business hours, External/public IP involved
<b>Likely false positive if:</b> Internal vulnerability scanner, User forgot password, Service account recently changed password

<h2>Successful Login After Failures</h2>

`index=windows (EventCode=4624 OR EventCode=4625)
| stats count by Account_Name, EventCode, Source_Network_Address`

<b>Detects:</b> Account compromise, Successful brute force
<b>Helps confirm true positive if:</b> 4625 failures immediately followed by 4624 success, Login from unusual geography/device, Privileged account involved
<b>Likely false positive if:</b> User eventually remembered password, VPN reconnect issue

<h2>PowerShell Execution</h2>

`index=windows EventCode=4104`

<b>Detects:</b> Malicious PowerShell, Living-off-the-land attacks, Malware execution
<b>Helps confirm true positive if:</b> Encoded commands, Base64 strings, DownloadString/WebClient usage, IEX execution, Suspicious URLs
<b>Likely false positive if:</b> IT automation scripts, SCCM/admin tooling, Legitimate management software
