# NextCloud file uploader validator

This program works both on Python 2.7.x and Python 3.x.

In order to use the program, you need to install the dependencies described at [requirements.txt](requirements.txt). The usage of an environment is recommended, in order to avoid conflicts with other existing system programs.

## Python 2.7.x
```bash
virtualenv -p python2 .pyVal2Env
source .pyVal2Env/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt
```

## Python 3.x
```bash
python3 -m venv .pyVal3Env
source .pyVal3Env/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt
```
