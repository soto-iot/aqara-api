# Aqara Developer API example

The Aqara developer platform provides HTTP APIs for remote calls by third-party applications, enabling device status query, remote control of devices, linkage configuration and other functions. In addition, through the message push service, real-time data reported by the device can be pushed to a third-party server.

> **Quick access to device, zero-code, low-code development, and intelligent linkage to realize the interconnection of everything.**

Through the API interface, query device information, control device, linkage configuration, etc.
For details, please refer to [API Introduction](https://opendoc.aqara.com/en/docs/developmanual/apiIntroduction.html) and [API List](https://opendoc.aqara.com/en/docs/developmanual/apiDocument.html)

### config.json

API Mainnet Config and API keys

```shell


1. Aqara API

China = 'https://open-cn.aqara.com'   // or
Korea = 'https://open-kr.aqara.com'   // or
USA = 'https://open-usa.aqara.com'    // or

"mainnet": "https://open-kr.aqara.com"

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

```
### main.py

```shell

$ touch main.py
from aqara_api import AqaraClient
...
...
client = AqaraClient(api_key='iloveiot!')
payload = {
    'appid': APPID ,
    'appkey': APPKEY , 
    'keyid': KEYID ,
    'email': email ,
    'virtual': virtual
}
response_data = client.get_auth(payload)

```

### Step by step

```shell
Step by step
1 Get Auth (get_auth)
2 Get Token (get_token)
3 Get List (get_position)
4 Get Attributes (get_resource)
5 Write (write_resource)
6 Read (read_resource)
7 Get History (get_history)

```

### Starting the app

The most basic and easy way to run a Python script is by using the python command. You need to open a command line and type the word python followed by the path to your script file like this:

```python
$ python main.py
```

