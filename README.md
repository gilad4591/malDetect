# MalDetect ⚠️

## Description
MalDetect was built to check if the computer communicate with malicious ip addresses.
It checks any suspicios ip that the computer communicate and transfer large amount of packets in 30 sec by using sniff of scapy library
and enter the ip address into the CHECKPHISH API, if the ip address associated with Scam/Phising etc.. it will alert and pop a dialog message to user.
 
## Development Environment:
* Windows 10
* Python 3.7
* Pycharm 2020.2.3

## Required Libraries/API
* Scapy
* time
* pprint
* sys
* argparse
* os
* ctypes
* <b> Checkphish API </b>

## How to run
before you run it, you should get an API key from https://checkphish.ai/checkphish-api/ <p></p>
After that, simply clone the project, run it from any IDE, and then click start.
it will do the rest by itself 😉



## Screenshots
<em>Simple gui<p></p></em>
<img src="https://github.com/gilad4591/malDetect/blob/master/Screenshots/ss1.jpg?raw=true" width = "250" height = "100" />
<em>Sniffing<p></p></em>
<img src="https://github.com/gilad4591/malDetect/blob/master/Screenshots/ss2.jpg?raw=true" width = "250" height = "100" />
<em>Found suspicios ip address<p></p></em>
<img src="https://github.com/gilad4591/malDetect/blob/master/Screenshots/ss4.jpg" width = "250" height = "100" />
<em>Alert<p></p></em>
<img src="https://github.com/gilad4591/malDetect/blob/master/Screenshots/ss3.jpeg" width = "250" height = "100" />



