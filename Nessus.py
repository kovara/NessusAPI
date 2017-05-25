import requests
import json
import sys

class Nessus:
	def __init__(self, url):
		self.url = url
		self.username = None
		self.password = None
		self.token = None
		self.secretKey = None
		self.accessKey = None
		
	def login(self, username, password):
		"""
		Function to log in and set class token values for other class functions to use
		"""
		self.username = username
		self.password = password
		
		creds = {"username":username,"password":password}
		
		r = requests.post(self.url+"/session", data=creds, verify=False)
		if r.status_code != 200: 
			raise ValueError("Login failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		self.token = json.loads(r.text)["token"]
		self.getKeys()
		
	def requestHandler(self, HTTPMethod, uri, data=None, header="token", retry_limit=30):
		"""
		Generalized function to make calls to REST API
		It can also be used as a general function for sending commands and returning data
		"""
		if header == "token": headers={"X-Cookie":"token="+self.token,"Content-Type":"application/json"}
		if header == "apikeys": headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";","Content-Type":"application/json"}
		i = 0
		while i < 30:
			i += 1
			try:
				if HTTPMethod == "GET": 
					r = requests.get(self.url+uri, headers=headers, data=json.dumps(data), verify=False)
				elif HTTPMethod == "PUT": 
					r = requests.put(self.url+uri, headers=headers, data=json.dumps(data), verify=False)
				elif HTTPMethod == "DELETE": 
					r = requests.DELETE(self.url+uri, headers=headers, data=json.dumps(data), verify=False)
				elif HTTPMethod == "POST": 
					r = requests.post(self.url+uri, headers=headers, data=json.dumps(data), verify=False)
				else:
					raise ValueError("HTTP Method not understood")
			except requests.exceptions.ConnectionError as e:
				sys.stderr.write("Unexpected Error, unable to communicate with Nessus server: %s \n retrying...", e)
			
		if r.status_code != 200: 
			raise ValueError("Communication failed with error: "+str(r.status_code)+"\n"+r.text)
			
		return r
	def getKeys(self):
		r = requests.put(self.url+"/session/keys", headers={"X-Cookie":"token="+self.token}, verify=False)
		if r.status_code != 200: 
			raise ValueError("getKeys failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		self.accessKey = json.loads(r.text)["accessKey"]
		self.secretKey = json.loads(r.text)["secretKey"]

	def setKeys(self, accessKey, secretKey):
		self.accessKey = accessKey
		self.secretKey = secretKey
		
	def getPolicyID(self, policy_name):
		# takes exact name of policy and returns ID
		r = requests.get(self.url+"/policies", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, verify=False)
		if r.status_code != 200: 
			raise ValueError("getPolicyID failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		js = json.loads(r.text)
		for p in js["policies"]:
			if p["name"] == policy_name:
				return p["id"]
		raise UserWarning("Policy with name: "+policy_name+" not found")
	
	def getPolicyUUID(self, policy_id):
		#takes policy ID and returns uuid
		r = requests.get(self.url+"/policies/"+str(policy_id), headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, verify=False)
		if r.status_code != 200: 
			raise ValueError("copyPolicy failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		uuid = json.loads(r.text)["uuid"]
		return uuid
		
	def copyPolicy(self, policyID):
		#copies policy by ID and returns new policy id
		r = requests.post(self.url+"/policies/"+str(policyID)+"/copy", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, verify=False)
		if r.status_code != 200: 
			raise ValueError("copyPolicy failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		return json.loads(r.text)["id"]
	
	def modifyPolicy(self, policy_id, data):
		#modifies policy with custom data json.  Sample syntax:
		#  data = {'settings': {'portscan_range':"default,22,80,443",'name': "Example Name",'description': 'Example Description',}}
	
		r = requests.put(self.url+"/policies/"+str(policy_id), headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";","Content-Type":"application/json"}, data=json.dumps(data), verify=False)
		if r.status_code != 200: 
			raise ValueError("modifyNessusPolicy failed: "+str(r.status_code)+"\n"+r.text)
	
	def createScan(self, name, policy_id, hosts):
		#creates nessus scan with specified name, hosts and uses policy with policy_id.
		policy_uuid = self.getPolicyUUID(policy_id)
		
		data = {"uuid":policy_uuid,"settings":{"name":name,"description":"Created by Script","emails":"","enabled":"true","launch":"ON_DEMAND","policy_id":policy_id,"text_targets":hosts,"use_dashboard":"true"}}
		r = requests.post(self.url+"/scans", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";","Content-Type":"application/json"}, data=json.dumps(data), verify=False)
		if r.status_code != 200: 
			raise ValueError("createScan failed: "+str(r.status_code)+"\n"+r.text)
			
		return json.loads(r.text)
	
	def getScanDetails(self, scan_id):
		r = requests.get(self.url+"/scans/"+str(scan_id), headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, verify=False)
		if r.status_code != 200: 
			raise ValueError("getScanDetails failed: "+str(r.status_code)+"\n"+r.text)
			
		return json.loads(r.text)
		
	def getScanStatus(self, scan_id):
		r = requests.get(self.url+"/scans/"+str(scan_id), headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, verify=False)
		if r.status_code != 200: 
			raise ValueError("getScanStatus failed: "+str(r.status_code)+"\n"+r.text)
			
		return json.loads(r.text)['info']['status']
		
	def launchScan(self, scan_id):
		r = requests.post(self.url+"/scans/"+str(scan_id)+"/launch", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, verify=False)
		if r.status_code != 200: 
			raise ValueError("launchScan failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		return r

			
	def pauseScan(self, scan_id):
		r = requests.post(self.url+"/scans/"+str(scan_id)+"/pause", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, verify=False)
		if r.status_code != 200: 
			raise ValueError("pauseScan failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		return r

	def resumeScan(self, scan_id):
		r = requests.post(self.url+"/scans/"+str(scan_id)+"/resume", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, verify=False)
		if r.status_code != 200: 
			raise ValueError("resumeScan failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		return r

			
	def dlResults(self, scan_id, format, password=None, chapters=None, timeout=30):
		#returns string of scan results.  Write the string to file with .nessus or .html extension
		import time
		if format != "nessus" and format != "html":
			raise ValueError("format not understood or not implemeneted")
			
		data={"format": format}
		if chapters is not None: data={"format": format, "chapters": chapters}

		r = requests.post(self.url+"/scans/"+str(scan_id)+"/export", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";","Content-Type":"application/json"}, data=json.dumps(data), verify=False)
	
		file_id = json.loads(r.text)["file"]

		for i in range(timeout):
			p = requests.get(self.url+"/scans/"+str(scan_id)+"/export/"+str(file_id)+"/download", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";","Content-Type":"application/json"}, verify=False)
			#report may take awhile to generate, loop until it's ready
			if p.status_code != 200:
				time.sleep(1)
				continue
			file_contents = p.text
			break
		
		return file_contents
		
	def uploadScan(self, file):
		#reads in .nessus file, uploads and returns id
		#upload file
		r = requests.post(self.url+"/file/upload", headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";"}, files={"Filedata": open(file,"rb")}, verify=False)
		if r.status_code != 200:
			raise ValueError("upload file failed with error code: "+str(r.status_code)+"\n"+r.text)
			
		file_uploaded = json.loads(r.text)["fileuploaded"]		
		
		#import scan
		data = {"file":file_uploaded}
		r = requests.post(self.url+"/scans/import",headers={"X-ApiKeys": "accessKey="+self.accessKey+"; secretKey="+self.secretKey+";","Content-Type":"application/json"}, data=json.dumps(data), verify=False)
		
		if r.status_code != 200:
			raise ValueError("import scan failed with error code: "+str(r.status_code)+"\n"+r.text)
		
		return json.loads(r.text)["scan"]["id"]
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
