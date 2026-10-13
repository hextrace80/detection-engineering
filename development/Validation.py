import tomllib
import sys
import os
# file ="Alert_Example.toml"

# with open(file,"rb") as toml:
#     alert = tomllib.load(toml)


for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
          full_path = os.path.join (root, file)
          with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
            # print(alert)
                
                
                present_fields=[]
                missing_fields =[]


                if alert ['rule'] ['type'] == "query" :
                    required_fields =[ 'description', 'name','rule_id', 'risk_score','severity', 'type', 'query'  ]

                elif  alert ['rule'] ['type'] == "eql" :
                    required_fields =[ 'description', 'name','rule_id', 'risk_score','severity', 'type', 'query', 'language' ]

                elif alert ['rule'] ['type'] == "threshold" :
                    required_fields =[ 'description', 'name','rule_id', 'risk_score','severity', 'type', 'query' ,'threshold' ]

                else:
                    print("Unsupported rule type found in: " + full_path)
                    break

                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)


                for field in required_fields:
                 if field not in present_fields:
                    missing_fields.append(field)
                
                
                if missing_fields:
                    print("The following fields do not exist in " + file +": " + str(missing_fields))

                else:
                    print( "Validation Passed for: " + file)