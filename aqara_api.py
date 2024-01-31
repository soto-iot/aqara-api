#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@Author: Soto
@Date: 2023/05/12
@Version: 20230512
@API Document URL : https://opendoc.aqara.cn/en/

"""

import requests
import json
import hashlib
import time
import logging
import traceback
import pprint
import os
from datetime import datetime

MAINNET  = ''


''' 
$ touch config.json
{
    "mainnet": "https://open-kr.aqara.com",
    "appid": "11111111111111",
    "appkey": "222222222222",
    "keyid": "333333333333333",
    "email": "aaaa@aaaa.com" ,
    "machineName": "aaaa",
    "version": "55555",
    "buildNumber": "55555"
}

$ touch main.py
client = AqaraClient(api_key='iloveiot!')
payload = {
    'appid': APPID ,
    'appkey': APPKEY , 
    'keyid': KEYID ,
    'email': email ,
    'virtual': virtual
}
response_data = client.get_auth(payload)

Step by step
1 Get Auth (get_auth)
2 Get Token (get_token)
3 Get List (get_position)
4 Get Attributes (get_resource)
5 Write (write_resource)
6 Read (read_resource)
7 Get History (get_history)
'''

with open('config.json', encoding="utf-8") as jsonFile:
    jsonData = json.load(jsonFile)

    MAINNET = jsonData["mainnet"]
    print('MAINNET: ', MAINNET)

# MAINNET = 'https://open-cn.aqara.com'
# MAINNET = 'https://open-kr.aqara.com'
# MAINNET = 'https://open-usa.aqara.com'

APIURL = MAINNET + '/v3.0/open/api'
TOKENURL = MAINNET + '/v3.0/open/access_token'
AUTHURL = MAINNET + '/v3.0/open/authorize'

class AqaraClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.api_id = ''
        self.api_key = ''
        self.key_id = ''
    
    def get_headers(self, accessToken, appid, appkey , keyid):
        try:        
            logging.info('[get_headers] appid : ' + str(appid))
            logging.info('[get_headers] appkey : ' + str(appkey))
            logging.info('[get_headers] keyid : ' + str(keyid))

            currentUTC = str(round(time.time(), 3))
            Appid = appid
            Keyid = keyid
            AppKey = appkey
            Time = currentUTC.replace('.', '')
            Nonce = currentUTC.replace('.', '')

            headers = ''
            
            if accessToken == 'No':
                accessToken = ''
                preSign = 'Appid=' + Appid + '&' + 'Keyid=' + Keyid + '&' + 'Nonce=' + Nonce + '&' + 'Time=' + Time + AppKey

                preSign = preSign.lower()
                Sign = str(hashlib.md5(preSign.encode()).hexdigest())

                headers = {
                    'Content-Type' : 'application/json',
                    'Appid': Appid,
                    'Keyid': Keyid,
                    'Nonce': Nonce,
                    'Time': Time,
                    'Sign': Sign
                    # 'Lang': 'ko'
                }
            else:
                preSign = 'Accesstoken=' + accessToken + '&' + 'Appid=' + Appid + '&' + 'Keyid=' + Keyid + '&' + 'Nonce=' + Nonce + '&' + 'Time=' + Time + AppKey
                preSign = preSign.lower()
                Sign = str(hashlib.md5(preSign.encode()).hexdigest())

                headers = {
                    'Content-Type' : 'application/json',
                    'Accesstoken': accessToken,
                    'Appid': Appid,
                    'Keyid': Keyid,
                    'Nonce': Nonce,
                    'Time': Time,
                    'Sign': Sign
                    # 'Lang': 'ko'
                }

            logging.info('[get_headers] header : ' + str(headers))

            return headers
        
        except Exception as error:
            logging.info('[get_headers] traceback : ' + str(traceback.format_exc()))
            return None
    

    def virtual_account(self, payload):

        appid = payload.get('appid')
        appkey = payload.get('appkey')
        keyid = payload.get('keyid')
        email = payload.get('email')

        logging.info('[virtual_account] Payload email : ' + str(email))
        logging.info('[virtual_account] Payload appid : ' + str(appid))

        accessToken = 'No'

        headers = self.get_headers(accessToken, appid, appkey , keyid)

        payload = {
            'intent': 'config.auth.createAccount',
            'data': {
                'accountId': email ,
                "remark": "lumi-1"  
            }
        }

        payload = json.dumps(payload) 

        try:
            openId = ''            
            response = requests.post(APIURL, headers=headers, data=payload)         
            response = json.loads(response.text)
            logging.info('[virtual_account] response : ' + str(response))
            result = response['message']

            if result == 'Success' :
                openId = response['result']['openId']

            return openId, response

        except Exception as error:
            logging.info('[virtual_account] traceback : ' + str(traceback.format_exc()))
            return None

    def get_authorize_code(self, payload):

        appid = payload.get('appid')
        appkey = payload.get('appkey')
        keyid = payload.get('keyid')
        email = payload.get('email')
        virtual = payload.get('virtual')

        logging.info('[get_authorize_code] Payload appid : ' + str(appid))
        logging.info('[get_authorize_code] Payload virtual : ' + str(virtual))

        accessToken = 'No'
        account_type = 0

        if virtual :
            account_type = 2
            openId, response = self.virtual_account(payload)
            logging.info('[get_authorize_code] response openId : ' + str(openId))
            logging.info('[get_authorize_code] response : ' + str(response))

        headers = self.get_headers(accessToken, appid, appkey , keyid)

        payload = {
            'intent': 'config.auth.getAuthCode',
            'data': {
                'account': email ,
                'accountType': account_type ,
                'accessTokenValidity': '1y'
            }
        }

        logging.info('[get_authorize_code] payload : ' + str(payload))

        payload = json.dumps(payload) 

        try:            
            response = requests.post(APIURL, headers=headers, data=payload)            
            response = json.loads(response.text)
            logging.info('[get_authorize_code] payload : ' + str(response))
            return response

        except Exception as error:
            logging.info('[get_authorize_code] traceback : ' + str(traceback.format_exc()))
            return None
    
    def get_access_token(self, payload):

        logging.info('[get_access_token] Payload : ' + str(payload))
        
        appid = payload.get('appid')
        appkey = payload.get('appkey')
        keyid = payload.get('keyid')
        email = payload.get('email')
        authCode = payload.get('authCode')
        virtual = payload.get('virtual')

        accessToken = 'No'
        account_type = 0

        if virtual :
            account_type = 2

        headers = self.get_headers(accessToken, appid, appkey , keyid)
        payload = {
            "intent": "config.auth.getToken",
            "data": {
                "authCode": authCode,
                "account": email,
                "accountType": account_type
            }
        }

        logging.info('[get_access_token] payload : ' + str(payload))
        
        try:
            response = requests.post(APIURL, headers=headers, json=payload)
            response = json.loads(response.text)
            print('[get_access_token] response : ', response)
            accessToken = response['result']['accessToken']
            return accessToken, response
        
        except Exception as error:
            logging.info('[get_access_token] traceback : ' + str(traceback.format_exc()))
            accessToken = ''
            response = ''
            return accessToken, response
    
    def get_position_info(self, payload):

        logging.info('[get_position_info] Payload : ' + str(payload))
        
        accessToken = payload.get('token')
        appid = payload.get('appid')
        appkey = payload.get('appkey')
        keyid = payload.get('keyid')

        response = ''
        all_position_value = []
        all_device_list = []        

        headers = self.get_headers(accessToken, appid, appkey , keyid)
        tempPayload = {
            "intent": "query.position.info",
            "data": {
                "pageNum": 1,
                "pageSize": 200
            }
        }
        
        try:
            response = requests.post(APIURL, headers=headers, json=tempPayload)

            positionResponse = json.loads(response.text)
            logging.info("response : " + str(positionResponse))
            resultValue = positionResponse['result']['data']
            logging.info("[get_position_info] all_device_list :  " + str(resultValue))

            for dataSet in resultValue:
                logging.info("dataSet : " + str(dataSet))
                temp = {'positionName': dataSet['positionName'], 'positionId': dataSet['positionId']}
                all_position_value.append(temp)

            logging.info("positionId : " + str(all_position_value))
            pprint.pprint(all_position_value)
            # pprint.pprint(response)

            if all_position_value :

                for dataSet in all_position_value:
                    responseList = self.aiot_device_list(dataSet['positionId'] , payload)
                    all_device_list.append(responseList)

            logging.info("[get_position_info] all_device_list :  " + str(all_device_list))
            return all_position_value, positionResponse, all_device_list
        
        except Exception as error:
            logging.info('[get_position_info] traceback : ' + str(traceback.format_exc()))
            access_token = ''
            response = ''
            return access_token, response , ''
    
    def aiot_device_list(self, positionId, payload):
        try:
            logging.info('[aiot_device_list] Payload : ' + str(payload))
            accessToken = payload.get('token')
            appid = payload.get('appid')
            appkey = payload.get('appkey')
            keyid = payload.get('keyid')

            all_dev_list_value = []

            headers = self.get_headers(accessToken, appid, appkey , keyid)

            tempPayload = {
                "intent": "query.device.info",
                "data": {
                    "positionId": positionId ,
                    "pageNum": 1,
                    "pageSize": 200
                }
            }

            payload = str(json.dumps(tempPayload))
            response = requests.post(APIURL, headers=headers, data=payload)
            response = json.loads(response.text)
            logging.info("response : " + str(response))
            resultValue = response['result']['data']

            for dataSet in resultValue:
                logging.info("dataSet : " + str(dataSet))
                temp = {'deviceName': dataSet['deviceName'], 'state': dataSet['state'] , 'model': dataSet['model'] , 'did': dataSet['did'] }
                all_dev_list_value.append(temp)

            return all_dev_list_value
        
        except Exception as error:
            logging.info('[aiot_device_list] traceback : ' + str(traceback.format_exc()))
            return 'aiot_device_list'
    
    def query_resource_info(self, payload):    
        response = ''    
        try:
            logging.info('[query_resource_info] Payload : ' + str(payload))
            model = payload.get('model')
            accessToken = payload.get('token')
            appid = payload.get('appid')
            appkey = payload.get('appkey')
            keyid = payload.get('keyid')

            model_info_value = []            

            headers = self.get_headers(accessToken, appid, appkey , keyid)

            tempPayload = {
                "intent": "query.resource.info",
                "data": {
                    "model": model 
                }
            }

            payload = str(json.dumps(tempPayload))
            response = requests.post(APIURL, headers=headers, data=payload)
            response = json.loads(response.text)
            logging.info("response : " + str(response))
            resultValue = response['result']

            for dataSet in resultValue:
                logging.info("dataSet : " + str(dataSet))
                temp = {'name': dataSet['name'], 'resourceId': dataSet['resourceId'] , 'access': dataSet['access'] , 'description': dataSet['description'] }
                model_info_value.append(temp)

            return model_info_value , response
        
        except Exception as error:
            logging.info('[query_resource_info] traceback : ' + str(traceback.format_exc()))
            return 'query_resource_info' , response
    
    def write_resource_device(self, payload):        
        try:
            logging.info('[write_resource_device] Payload : ' + str(payload))
            appid = payload.get('appid')
            appkey = payload.get('appkey')
            keyid = payload.get('keyid')
            did = payload.get('did')
            resid = payload.get('resid')
            control = payload.get('control')
            accessToken = payload.get('token')
            
            value = 1 if control == 'on' else 0

            headers = self.get_headers(accessToken, appid, appkey , keyid)
         
            tempPayload = {
                "intent": "write.resource.device",
                "data": [
                    {
                        "subjectId": did ,
                        "resources": [
                            {
                            "resourceId": resid ,
                            "value": value
                            }
                        ]
                    }
                ]
            }

            payload = str(json.dumps(tempPayload))
            response = requests.post(APIURL, headers=headers, data=payload)
            response = json.loads(response.text)
            logging.info("response : " + str(response))

            return response
        
        except Exception as error:
            logging.info('[write_resource_device] traceback : ' + str(traceback.format_exc()))
            return 'write_resource_device'
    
    def query_resource_value(self, payload):
        try:
            logging.info('[query_resource_value] Payload : ' + str(payload))
            appid = payload.get('appid')
            appkey = payload.get('appkey')
            keyid = payload.get('keyid')
            did = payload.get('did')
            resid = payload.get('resid')
            accessToken = payload.get('token')
            
            resid = [s.strip() for s in resid.split(",")]

            headers = self.get_headers(accessToken, appid, appkey , keyid)
         
            tempPayload = {
                "intent": "query.resource.value",
                "data": {
                    "resources": [ 
                    {
                        "subjectId": did ,
                        "resourceIds": 
                            resid                        
                    }
                    ]
                }
            }

            logging.info("[query_resource_value] tempPayload : " + str(tempPayload))

            payload = str(json.dumps(tempPayload))
            response = requests.post(APIURL, headers=headers, data=payload)
            response = json.loads(response.text)
            logging.info("response : " + str(response))

            return response
        
        except Exception as error:
            logging.info('[query_resource_value] traceback : ' + str(traceback.format_exc()))      
            return 'query_resource_value'
        
    def fetch_resource_history(self, payload):
        try:
            logging.info('[fetch_resource_history] Payload : ' + str(payload))
            print("[fetch_resource_history].. ")
            appid = payload.get('appid')
            appkey = payload.get('appkey')
            keyid = payload.get('keyid')
            did = payload.get('did')
            resid = payload.get('resid')
            accessToken = payload.get('token')

            headers = self.get_headers(accessToken, appid, appkey , keyid)
         
            currentUTC = str(round(time.time(),3) - 86400 * 30 )  # 86400 = 24H : 60s * 60m * 24h
            tTime = currentUTC.replace('.','')

            tempPayload = {
                "intent": "fetch.resource.history",
                "data": {
                    "subjectId": did ,
                    "resourceIds": [
                        resid
                    ],   
                    "startTime": tTime                     
                }                
            }

            payload = str(json.dumps(tempPayload))
            response = requests.post(APIURL, headers=headers, data=payload)
            response = json.loads(response.text)
            logging.info("response : " + str(response))

            return response
        
        except Exception as error:
            logging.info('[fetch_resource_history] traceback : ' + str(traceback.format_exc()))         
            return 'write_resource_device'


    """
    @get_auth
    payload = {
        'appid': APPID ,
        'appkey': APPKEY , 
        'keyid': KEYID ,
        'email': email ,
        'virtual': virtual
    }
    """
    def get_auth(self, payload):
        try:
            logging.info('[get_auth] Payload : ' + str(payload))
            authorizeCode = self.get_authorize_code(payload)
            return authorizeCode  
        
        except Exception as error:          
            logging.info('[get_auth] traceback : ' + str(traceback.format_exc()))
            return None

    """
    @get_token
    payload = {
        'authCode': authCode,
        'appid': APPID,
        'appkey': APPKEY, 
        'keyid': KEYID,
        'email': email,
        'virtual': virtual
    }
    """        
    def get_token(self, payload):
        try:
            logging.info('[get_token] Payload : ' + str(payload))
            accessToken , response = self.get_access_token(payload)

            return accessToken , response 
        
        except Exception as error:
            logging.info('[get_token] traceback : ' + str(traceback.format_exc()))
            return None
    
    """
    @get_position
    payload = {
        'token': token,
        'appid': APPID,
        'appkey': APPKEY, 
        'keyid': KEYID
    }
    """  
    def get_position(self, payload):        
        try:
            logging.info('[get_position] Payload : ' + str(payload))
            all_position_value, positionResponse, all_device_list = self.get_position_info(payload)

            return all_position_value, positionResponse, all_device_list 
        
        except Exception as error:
            logging.info('[get_position] traceback : ' + str(traceback.format_exc()))
            return None
    
    """
    @get_resource
    payload = {
        'model': model,
        'token': token,
        'appid': APPID,
        'appkey': APPKEY, 
        'keyid': KEYID 
    }
    """ 
    def get_resource(self, payload):
        try:
            logging.info('[get_resource] Payload : ' + str(payload))
            device_resource_value, resourceResponse = self.query_resource_info(payload)

            return device_resource_value, resourceResponse 
        
        except Exception as error:
            logging.info('[get_resource] traceback : ' + str(traceback.format_exc()))
            return None
    
    """
    @write_resource
    payload = {
        'appid': APPID,
        'appkey': APPKEY, 
        'keyid': KEYID,
        'did': did,  
        'resid': resid,  
        'control': control,  
        'token': token
    }
    """ 
    def write_resource(self, payload):
        try:
            logging.info('[write_resource] Payload : ' + str(payload))
            resourceResponse = self.write_resource_device(payload)

            return resourceResponse  
        
        except Exception as error:
            logging.info('[write_resource] traceback : ' + str(traceback.format_exc()))
            return None
    
    """
    @read_resource
    payload = {
        'appid': APPID,
        'appkey': APPKEY, 
        'keyid': KEYID,
        'did': did,  
        'resid': resid,  
        'token': token
    }
    """ 
    def read_resource(self, payload):        
        try:
            logging.info('[read_resource] Payload : ' + str(payload))
            resourceResponse = self.query_resource_value(payload)

            return resourceResponse  
        
        except Exception as error:
            logging.info('[read_resource] traceback : ' + str(traceback.format_exc()))
            return None
    
    """
    @get_history
    payload = { 
        'appid': APPID,
        'appkey': APPKEY, 
        'keyid': KEYID,
        'did': did,   
        'resid': resid,   
        'token': token
    }
    """
    def get_history(self, payload):
        try:
            logging.info('[get_history] Payload : ' + str(payload))
            resourceResponse = self.fetch_resource_history(payload)

            return resourceResponse  
        
        except Exception as error:
            logging.info('[get_history] traceback : ' + str(traceback.format_exc()))
            return None

    

