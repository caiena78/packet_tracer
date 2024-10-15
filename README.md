# Run Packet-Tracert on Multi Cisco FTD/ASA

## Description
This web API runs packet tracer on multiple Cisco ASA/FTD devices simultaneously and returns the results.


## Installation
- pip install -r requirements.txt
- create a device.json file
- python3 web.py

## devices.json file
- location devices/devices.json
- format:
    [
    {
        "ip":"<IP>",
        "name": "<Devicename>",
        "location":"<location>",
        "inside": "<inside interface name>",
        "outside": "<outside interface name>",
        "deviceType": "cisco_asa",
        "user": "<env variable to use for username>",
        "password": "<env variable to use for password>",
        "enable":"<env variable to use for enable password>"
    },
     {
        "ip":"<IP>",
        "name": "<Devicename>",
        "location":"<location>",
        "inside": "<inside interface name>",
        "outside": "<outside interface name>",
        "deviceType": "cisco_ftd_ssh",
        "user": "<env variable to use for username>",
        "password": "<env variable to use for password>",
        "enable":"<env variable to use for enable password>"
    }
    ]

