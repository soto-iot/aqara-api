from datetime import datetime
import logging
import os
from aqara_api import AqaraClient
import traceback
import json
import time

from logs import Logs
logger = Logs(apikey='iloveapi!')

appid = ''
appkey = ''
keyid = ''
email = ''
mainnet = ''

with open('config.json', encoding="utf-8") as jsonFile:
    jsonData = json.load(jsonFile)    
    appid = jsonData["appid"]
    appkey = jsonData["appkey"]
    keyid = jsonData["keyid"]
    email = jsonData["email"]

client = AqaraClient(apikey='iloveiot!', appid=appid, appkey=appkey, keyid=keyid , email=email)

# writeDev('lumi.54ef44', '4.1.85', '1', '52ef070f140e80695369e' ) 
did = 'lumi.54ef44'
resid = '4.1.85'
value = '1'
token = '52ef070f140e80695369e'

# Left Button On POST 요청
payload = { 
    'did': did ,  
    'resid': resid ,  
    'control': value ,  
    'token': token
}

response_msg = client.write_resource(payload)

time.sleep(3)  # 3초 동안 지연

value = '0'

# Left Button Off POST 요청
payload = { 
    'did': did ,  
    'resid': resid ,   
    'control': value ,  
    'token': token
}

response_msg = client.write_resource(payload)

time.sleep(3)  # 3초 동안 지연

did = 'lumi.54ef44'
resid = '4.2.85'
value = '1'
token = '52ef070f140e80695369e'

# Right Button On POST 요청
payload = { 
    'did': did ,  
    'resid': resid ,  
    'control': value ,  
    'token': token
}

response_msg = client.write_resource(payload)

time.sleep(3)  # 3초 동안 지연

value = '0'

# Right Button Off POST 요청
payload = { 
    'did': did ,  
    'resid': resid ,   
    'control': value ,  
    'token': token
}

response_msg = client.write_resource(payload)
