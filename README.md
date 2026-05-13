 <h1>Splunk Searches for a SOC Analyst</h1>

 <h2>Failed Login Brute Force</h2>

 `index=windows EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 10`
