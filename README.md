 <h1>Splunk Searches for a SOC Analyst</h1>

 <h2>Failed Login Brute Force</h2>

 `index=windows EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 10`

<b>Detects:</b> Password spraying, Brute-force attacks<br>
<b>Helps confirm true positive if:</b> Many failures from one IP, Multiple usernames targeted, Happens outside business hours, External/public IP involved<br>
<b>Likely false positive if:</b> Internal vulnerability scanner, User forgot password, Service account recently changed password<br>

<h2>Successful Login After Failures</h2>

`index=windows (EventCode=4624 OR EventCode=4625)
| stats count by Account_Name, EventCode, Source_Network_Address`

<b>Detects:</b> Account compromise, Successful brute force<br>
<b>Helps confirm true positive if:</b> 4625 failures immediately followed by 4624 success, Login from unusual geography/device, Privileged account involved<br>
<b>Likely false positive if:</b> User eventually remembered password, VPN reconnect issue<br>

<h2>PowerShell Execution</h2>

`index=windows EventCode=4104`

<b>Detects:</b> Malicious PowerShell, Living-off-the-land attacks, Malware execution<br>
<b>Helps confirm true positive if:</b> Encoded commands, Base64 strings, DownloadString/WebClient usage, IEX execution, Suspicious URLs<br>
<b>Likely false positive if:</b> IT automation scripts, SCCM/admin tooling, Legitimate management software<br>

<h2>Suspicious Encoded PowerShell</h2>

`index=windows EventCode=4104 "*EncodedCommand*"`

<b>Detects:</b> Obfuscated malware, Red team activity<br>
<b>Helps confirm true positive if:</b> Randomized variable names, Network callbacks, AMSI bypass attempts<br>
<b>Likely false positive if:</b> Internal admin scripts using encoding<br>

<h2>New Local Admin Account Created</h2>

`index=windows EventCode=4720 OR EventCode=4732`

<b>Detects:</b> Privilege escalation, Persistence<br>
<b>Helps confirm true positive if:</b> Unexpected account name, Added to Administrators group, Performed by compromised account<br>
<b>Likely false positive if:</b> Approved IT onboarding, Scheduled maintenance<br>

<h2>RDP Logins</h2>

`index=windows EventCode=4624 Logon_Type=10`

<b>Detects:</b> Remote desktop access, Lateral movement<br>
<b>Helps confirm true positive if:</b> Login from unusual source, Admin account used, Odd login time<br>
<b>Likely false positive if:</b> Helpdesk activity, Remote employee login<br>

<h2>Multiple Accounts Locked Out</h2>

`index=windows EventCode=4740
| stats count by TargetUserName`

<b>Detects:</b> Password spraying, Authentication attacks<br>
<b>Helps confirm true positive if:</b> Many users affected quickly, Single source system involved<br>
<b>Likely false positive if:</b> Broken service account, Cached credentials issue<br>

<h2>Malware/AV Detection</h2>

`index=windows EventCode=1116`

<b>Detects:</b> Microsoft Defender malware alerts<br>
<b>Helps confirm true positive if:</b> Known malicious hash/path, Multiple hosts infected, Persistence artifacts present<br>
<b>Likely false positive if:</b> Security tools triggering AV, Internal pentest tools<br>

<h2>Suspicious Process Creation</h2>

`index=sysmon EventCode=1`

<b>Detects:</b> Malware execution, LOLBins, Initial access<br>
<b>Helps confirm true positive if:</b> Parent-child anomalies, Office spawning cmd/powershell, Temp/AppData execution<br>
<b>Likely false positive if:</b> Software installation, IT scripting<br>

<h2>Office Spawning PowerShell</h2>

`index=sysmon EventCode=1
(ParentImage="*winword.exe" OR ParentImage="*excel.exe")
Image="*powershell.exe"`

<b>Detects:</b> Malicious Office macros, Phishing payloads<br>
<b>Helps confirm true positive if:</b> Email attachment involved, Encoded commands, External downloads<br>
<b>Likely false positive if:</b> Rarely false positive, Usually worth escalation<br>

<h2>Network Connections from PowerShell</h2>

`index=sysmon EventCode=3 Image="*powershell.exe`

<b>Detects:</b> Command and control, Download cradles<br>
<b>Helps confirm true positive if:</b> External IPs, Rare domains, Known bad reputation<br>
<b>Likely false positive if:</b> Admin automation, Cloud management tooling<br>

<h2>DNS Requests to Suspicious Domains</h2>

`index=dns
| stats count by query`

<b>Detects:</b> C2 domains, Malware callbacks, Data exfiltration<br>
<b>Helps confirm true positive if:</b> DGA/random domains, Newly registered domains, High request volume<br>
<b>Likely false positive if:</b> CDN traffic, Security products<br>

<h2>DNS Requests to Suspicious Domains</h2>

`index=dns
| stats count by query`

<b>Detects:</b> C2 domains, Malware callbacks, Data exfiltration<br>
<b>Helps confirm true positive if:</b> DGA/random domains, Newly registered domains, High request volume<br>
<b>Likely false positive if:</b> CDN traffic, Security products<br

<h1>SOC Mapping</h1>

<b>Is this normal?</b>
Known user?
Known host?
Expected behavior?

<b>Is this malicious?</b>
Matches attack patterns?
Threat intel hit?
Suspicious timing?

<b>What is the impact?</b>
Single machine?
Domain-wide?
Privileged account?

<b>Escalate or close?</b>
Evidence of compromise?
Needs deeper investigation?







