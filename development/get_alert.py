
import requests
import os

url = "https://my-security-project-ed39ef.kb.us-east4.gcp.elastic.cloud/api/detection_engine/rules"
rule_id = "00000000-0000-0000-0000-000000000001"
params = {
    "rule_id": rule_id
}

api_key =  os.environ['ELASTIC_KEY']

headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": "ApiKey " + api_key
}

elastic_data = requests.get(url, headers=headers, params=params).json()
print (elastic_data)


