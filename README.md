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






