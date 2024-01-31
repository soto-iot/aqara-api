#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Author: Soto
@Date: 2023/05/12
@Version: 20230512
@API Document URL : https://opendoc.aqara.cn/en/

"""

from datetime import datetime
import logging
import os
from aqara_api import AqaraClient
import traceback
import json

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

client = AqaraClient(api_key='iloveiot!')
payload = {
    'appid': appid ,
    'appkey': appkey , 
    'keyid': keyid ,
    'email': email ,
    'virtual': False
}
response_data = client.get_auth(payload)
