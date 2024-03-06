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
from aqara_api import AqaraClient
client = AqaraClient(api_key='iloveiot!')
payload = {
    'virtual': False
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
    def __init__(self, appkey, appid, appkey, keyid, email):
        self.apiKey = apikey
        self.appId = appid
        self.appKey = appkey
        self.keyId = keyid
        self.email = email
    
    def get_headers(self, accessToken):
        try:        
            logging.info('[get_headers] appId : ' + str(self.appId))
            logging.info('[get_headers] appKey : ' + str(self.appKey))
            logging.info('[get_headers] keyId : ' + str(self.keyId))
       
            currentUTC = round(time.time(), 3)
            timeNow = str(int(currentUTC * 1000))
            nonce = str(int(currentUTC * 1000))

            logging.info('[get_headers] currentUTC : ' + str(currentUTC))

            headers = ''
            
            if accessToken == 'No':
                accessToken = ''
                preSign = f'Appid={self.appId}&Keyid={self.keyId}&Nonce={self.nonce}&Time={timeNow}{self.appKey}'

                preSign = preSign.lower()
                sign = str(hashlib.md5(preSign.encode()).hexdigest())

                headers = {
                    'Content-Type' : 'application/json',
                    'Appid': self.appId,
                    'Keyid': self.keyId,
                    'Nonce': nonce,
                    'Time': timeNow,
                    'Sign': sign
                    # 'Lang': 'ko'
                }
            else:
                
                preSign = f'Accesstoken={accessToken}&Appid={self.appId}&Keyid={self.keyId}&Nonce={self.nonce}&Time={timeNow}{self.appKey}'
                preSign = preSign.lower()
                sign = str(hashlib.md5(preSign.encode()).hexdigest())

                headers = {
                    'Content-Type' : 'application/json',
                    'Accesstoken': accessToken,
                    'Appid': self.appId,
                    'Keyid': self.keyId,
                    'Nonce': nonce,
                    'Time': timeNow,
                    'Sign': sign
                    # 'Lang': 'ko'
                }

            logging.info('[get_headers] header : ' + str(headers))

            return headers
        
        except Exception as error:
            logging.info('[get_headers] traceback : ' + str(traceback.format_exc()))
            return None
    

    def virtual_account(self, payload):

        logging.info('[virtual_account] Payload email : ' + str(self.email))
        logging.info('[virtual_account] Payload appId : ' + str(self.appId))

        accessToken = 'No'

        headers = self.get_headers(accessToken)

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

    
    '''
    virtual_account_auto
    needAccessToken:
      true: need to return accessToken; false: do not need to return accessToken
    accessTokenValidity:
      Access token valid time
    '''


    def virtual_account_auto(self, payload):

        logging.info('[virtual_account] Payload email : ' + str(self.email))
        logging.info('[virtual_account] Payload appid : ' + str(self.appId))

        accessToken = 'No'

        headers = self.get_headers(accessToken )

        payload = {
            'intent': 'config.auth.createAccount',
            'data': {
                'accountId': self.email ,
                "remark": "lumi-1"  ,
                "needAccessToken" : True, 
                "accessTokenValidity" : "1y"
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

        virtual = payload.get('virtual')

        logging.info('[get_authorize_code] Payload appid : ' + str(self.appId))
        logging.info('[get_authorize_code] Payload virtual : ' + str(virtual))

        accessToken = 'No'
        accountType = 0

        if virtual :
            accountType = 2
            openId, response = self.virtual_account(payload)
            logging.info('[get_authorize_code] response openId : ' + str(openId))
            logging.info('[get_authorize_code] response : ' + str(response))

        headers = self.get_headers(accessToken)

        payload = {
            'intent': 'config.auth.getAuthCode',
            'data': {
                'account': self.email ,
                'accountType': accountType ,
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
        
        authCode = payload.get('authCode')
        virtual = payload.get('virtual')

        accessToken = 'No'
        accountType = 0

        if virtual :
            accountType = 2

        headers = self.get_headers(accessToken)
        payload = {
            "intent": "config.auth.getToken",
            "data": {
                "authCode": authCode ,
                "account": self.email ,
                "accountType": accountType
            }
        }

        logging.info('[get_access_token] payload : ' + str(payload))
        payload = json.dumps(payload) 
        
        try:
            response = requests.post(APIURL, headers=headers, data=payload)
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

        response = ''
        allPositionValue = []
        allDeviceList = []        

        headers = self.get_headers(accessToken)
        payload = {
            "intent": "query.position.info",
            "data": {
                "pageNum": 1,
                "pageSize": 200
            }
        }

        payload = json.dumps(payload) 
        
        try:
            response = requests.post(APIURL, headers=headers, data=payload)

            positionResponse = json.loads(response.text)
            logging.info("response : " + str(positionResponse))
            resultValue = positionResponse['result']['data']
            logging.info("[get_position_info] allDeviceList :  " + str(resultValue))

            for dataSet in resultValue:
                logging.info("dataSet : " + str(dataSet))
                temp = {'positionName': dataSet['positionName'], 'positionId': dataSet['positionId']}
                allPositionValue.append(temp)

            logging.info("positionId : " + str(allPositionValue))
            pprint.pprint(allPositionValue)
            # pprint.pprint(response)

            if allPositionValue :

                for dataSet in allPositionValue:
                    responseList = self.aiot_device_list(dataSet['positionId'] , payload)
                    allDeviceList.append(responseList)

            logging.info("[get_position_info] allDeviceList :  " + str(allDeviceList))
            return allPositionValue, positionResponse, allDeviceList
        
        except Exception as error:
            logging.info('[get_position_info] traceback : ' + str(traceback.format_exc()))
            accessToken = ''
            response = ''
            return accessToken, response , ''
    
    def aiot_device_list(self, positionId, payload):
        try:
            logging.info('[aiot_device_list] Payload : ' + str(payload))
            accessToken = payload.get('token')

            allDevListValue = []

            headers = self.get_headers(accessToken)

            payload = {
                "intent": "query.device.info",
                "data": {
                    "positionId": positionId ,
                    "pageNum": 1,
                    "pageSize": 200
                }
            }

            payload = json.dumps(payload) 
            response = requests.post(APIURL, headers=headers, data=payload)
            response = json.loads(response.text)
            logging.info("response : " + str(response))
            resultValue = response['result']['data']

            for dataSet in resultValue:
                logging.info("dataSet : " + str(dataSet))
                temp = {'deviceName': dataSet['deviceName'], 'state': dataSet['state'] , 'model': dataSet['model'] , 'did': dataSet['did'] }
                allDevListValue.append(temp)

            return allDevListValue
        
        except Exception as error:
            logging.info('[aiot_device_list] traceback : ' + str(traceback.format_exc()))
            return 'allDevListValue'
    
    def query_resource_info(self, payload):    
        response = ''    
        try:
            logging.info('[query_resource_info] Payload : ' + str(payload))
            model = payload.get('model')
            accessToken = payload.get('token')

            modelInfoValue = []            

            headers = self.get_headers(accessToken)

            payload = {
                "intent": "query.resource.info",
                "data": {
                    "model": model 
                }
            }

            payload = json.dumps(payload) 
            response = requests.post(APIURL, headers=headers, data=payload)
            response = json.loads(response.text)
            logging.info("response : " + str(response))
            resultValue = response['result']

            for dataSet in resultValue:
                logging.info("dataSet : " + str(dataSet))
                temp = {'name': dataSet['name'], 'resourceId': dataSet['resourceId'] , 'access': dataSet['access'] , 'description': dataSet['description'] }
                modelInfoValue.append(temp)

            return modelInfoValue , response
        
        except Exception as error:
            logging.info('[query_resource_info] traceback : ' + str(traceback.format_exc()))
            return 'query_resource_info' , response
    
    def write_resource_device(self, payload):        
        try:
            logging.info('[write_resource_device] Payload : ' + str(payload))

            did = payload.get('did')
            resid = payload.get('resid')
            value = payload.get('value')
            accessToken = payload.get('token')

            headers = self.get_headers(accessToken)
         
            payload = {
                "intent": "write.resource.device",
                "data": [
                    {
                        "subjectId": did ,
                        "resources": [
                            {
                            "resourceId": resid ,
                            "value": int(value)
                            }
                        ]
                    }
                ]
            }

            payload = json.dumps(payload) 
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

            did = payload.get('did')
            resid = payload.get('resid')
            accessToken = payload.get('token')
            
            resid = [s.strip() for s in resid.split(",")]

            headers = self.get_headers(accessToken)
         
            payload = {
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

            logging.info("[query_resource_value] payload : " + str(payload))

            payload = json.dumps(payload) 
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

            did = payload.get('did')
            resid = payload.get('resid')
            accessToken = payload.get('token')

            headers = self.get_headers(accessToken)
         
            currentUTC = round(time.time(),3) - 86400 * 30  # 86400 = 24H : 60s * 60m * 24h
            tTime = str(int(currentUTC * 1000))

            payload = {
                "intent": "fetch.resource.history",
                "data": {
                    "subjectId": did ,
                    "resourceIds": [
                        resid
                    ],   
                    "startTime": tTime                     
                }                
            }

            payload = json.dumps(payload) 
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
        'authCode': authCode
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
        'token': token
    }
    """  
    def get_position(self, payload):        
        try:
            logging.info('[get_position] Payload : ' + str(payload))
            allPositionValue, positionResponse, allDeviceList = self.get_position_info(payload)

            return allPositionValue, positionResponse, allDeviceList 
        
        except Exception as error:
            logging.info('[get_position] traceback : ' + str(traceback.format_exc()))
            return None
    
    """
    @get_resource
    payload = {
        'model': model,
        'token': token
    }
    """ 
    def get_resource(self, payload):
        try:
            logging.info('[get_resource] Payload : ' + str(payload))
            deviceResourceValue, resourceResponse = self.query_resource_info(payload)

            return deviceResourceValue, resourceResponse 
        
        except Exception as error:
            logging.info('[get_resource] traceback : ' + str(traceback.format_exc()))
            return None
    
    """
    @write_resource
    payload = {
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

    

