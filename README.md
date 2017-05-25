# NessusAPI
Python Library for Nessus 6.x REST Interface 

# Example Usage:
```
from Nessus import Nessus
```
## login
```
nessus = Nessus("https://127.0.0.1:8834")
nessus.login("username","password")
```
## create new policy
```
template_policy_id = nessus.getPolicyID("Sample Policy")
policy_id = nessus.copyPolicy(template_policy_id)
```
## modify policy
```
data = {"settings": {"portscan_range":"default,22,80,443","name": "Test Scan","description": "Created by Script",}}
nessus.modifyNessusPolicy(policy_id, data)
```
## create scan
```
scan = nessus.createNessusScan("Test Scan", policy_id, "127.0.0.1")
scan_id = scan["scan"]["id"]
```
## launch scan
```
nessus.launchNessusScan(scan_id)
```

	

