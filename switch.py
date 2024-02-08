from datetime import datetime
import logging
import os
from aqara_api import AqaraClient
import traceback
import json
import time

# 로그 파일을 저장할 디렉토리 경로를 설정합니다.
log_dir = 'logs'

# 로그 디렉토리가 존재하지 않으면 생성합니다.
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 현재 날짜를 기반으로 로그 파일명을 생성합니다.
log_filename = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

# 로그 파일의 전체 경로를 생성합니다.
log_file_path = os.path.join(log_dir, log_filename)

# 로깅 설정을 구성합니다.
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s]: %(message)s',
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler()
    ]
)

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
