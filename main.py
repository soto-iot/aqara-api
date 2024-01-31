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

log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_filename = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
log_file_path = os.path.join(log_dir, log_filename)
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
