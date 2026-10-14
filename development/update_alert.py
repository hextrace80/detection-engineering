import requests
import os
import tomllib

url = "https://my-security-project-ed39ef.kb.us-east4.gcp.elastic.cloud/api/detection_engine/rules"

api_key =  os.environ['ELASTIC_KEY']

headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": "ApiKey " + api_key
}


changed_files = os.environ["CHANGED_FILES"]


for root, dirs, files in os.walk("detections/"):
    for file in files:
      if file in changed_files:
        if file.endswith(".toml"):
          full_path = os.path.join (root, file)
          with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)

                if alert ['rule'] ['type'] == "query" :
                     required_fields =[  'author','description', 'name','rule_id', 'risk_score','severity', 'type', 'query', 'threat'  ]
                
                elif  alert ['rule'] ['type'] == "eql" :
                    required_fields =[ 'author', 'description', 'name','rule_id', 'risk_score','severity', 'type', 'query', 'language', 'threat'  ]
                
                elif alert ['rule'] ['type'] == "threshold" :
                    required_fields =[ 'author', 'description', 'name','rule_id', 'risk_score','severity', 'type', 'query' ,'threshold', 'threat'  ]
                
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break


                payload = {
                  field: alert["rule"][field]
                  for field in required_fields
                  if field in alert["rule"]
                }

                payload["enabled"] = True

        


     
       

    rule_id = alert["rule"]["rule_id"]
    update_url=url + "?rule_id=" + rule_id
              
       
    import json
       
              
               
       
    response = requests.put(update_url, headers=headers, json=payload, timeout=30)
    print("PUT status:", response.status_code)
    print("PUT response:", response.text)
    
    if response.status_code == 404:
        print("Rule does not exist. Trying POST to create it.")
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        print("POST status:", response.status_code)
        print("POST response:", response.text)

    response.raise_for_status()
    print(json.dumps(payload, indent=2))
    print(response.status_code)
    print(response.text)
        
       
           # elastic_data = requests.post(url, headers=headers, data=data).json()
           # print (elastic_data)