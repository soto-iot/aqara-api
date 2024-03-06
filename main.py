from datetime import datetime
import logging
import os
from aqara_api import AqaraClient
import traceback
import json

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

# 1 Get Auth (get_auth)
def get_auth():
    print('=== 1 Get Auth (get_auth)')
    payload = {
        'virtual': False
    }

    response = client.get_auth(payload)
    authCode = input(f'{email} 이메일을 확인하여 authCode 입력하세요: ')
    return authCode

# 2 Get Token (get_token)
def get_token(authCode):
    print('=== 2 Get Token (get_token)')
    payload = {
        'virtual': False ,
        'authCode': authCode    
    }

    accessToken, response = client.get_token(payload)

    logger.info('[get_token] accessToken : ' + str(accessToken))
    logger.info('[get_token] response : ' + str(response))
    return accessToken, response

# 3 Get List (get_position)
def get_position(accessToken):
    print('=== 3 Get List (get_position)')
    payload = {
        'token': accessToken
    }

    allPositionValue, response, allDeviceList = client.get_position(payload)

    logger.info('[get_position] allPositionValue : ' + str(allPositionValue))
    logger.info('[get_position] response : ' + str(response))
    return response

# 4 Get Attributes (get_resource)
def get_resource(accessToken):    
    print('=== 4 Get Attributes (get_resource)')
    model = input('model 확인하여 입력하세요: ')

    payload = {
        'model' : model ,
        'token': accessToken
    }

    modelInfoValue , response = client.get_resource(payload)

    logger.info('[get_resource] modelInfoValue : ' + str(modelInfoValue))
    logger.info('[get_resource] response : ' + str(response))
    return response

# 5 Write (write_resource)
def write_resource(accessToken):
    print('=== 5 Write (write_resource)')
    did = input('did 확인하여 입력하세요: ')
    resid = input('resid 확인하여 입력하세요: ')
    value = input('value 확인하여 입력하세요: ')

    payload = {
        'did' : did ,
        'resid' : resid ,
        'value' : value ,
        'token': accessToken
    }

    response = client.write_resource(payload)
    logger.info('[write_resource] response : ' + str(response))
    return response


# 6 Read (read_resource)
def read_resource(accessToken):
    print('=== 6 Read (read_resource)')
    did = input('did 확인하여 입력하세요: ')
    resid = input('resid 확인하여 입력하세요: ')

    payload = {
        'did' : did ,
        'resid' : resid ,
        'token': accessToken
    }

    response = client.read_resource(payload)
    logger.info('[read_resource] response : ' + str(response))
    return response

# 7 Get History (get_history)
def get_history(accessToken):
    print('=== 7 Get History (get_history)')
    did = input('did 확인하여 입력하세요: ')
    resid = input('resid 확인하여 입력하세요: ')

    payload = {
        'did' : did ,
        'resid' : resid ,
        'token': accessToken
    }

    response = client.get_history(payload)
    logger.info('[get_history] response : ' + str(response))
    return response

def main():
    '''
    Step by step
    1 Get Auth (get_auth)
    2 Get Token (get_token)
    3 Get List (get_position)
    4 Get Attributes (get_resource)
    5 Write (write_resource)
    6 Read (read_resource)
    7 Get History (get_history)
    '''
    authCode = get_auth()
    accessToken, response = get_token(authCode)
    response = get_position(accessToken)
    response = get_resource(accessToken)
    response = write_resource(accessToken)
    response = read_resource(accessToken)
    response = get_history(accessToken)

if __name__ == '__main__':
    main()    