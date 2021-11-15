# 
# MIT License
# 
# Copyright (c) 2021 d-wizard
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import socket
from scapy.all import *
import time
from datetime import datetime
import json

################################################################################
# Constant Variables
################################################################################
THIS_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
THIS_SCRIPT_FILENAME_NO_EXT = os.path.splitext(os.path.realpath(__file__))[0] 
JSON_PATH = THIS_SCRIPT_FILENAME_NO_EXT + '.json'

################################################################################
# Global Variables
################################################################################

# Settings
settingsDict = dict()
macAddrTrigger = ""

# Log variables
logNewLine = '\n'
logMaxLogLines_short = 5000
logLineToLeaveAfterTrim_short = 3000
logMaxLogLines_long = 50000
logLineToLeaveAfterTrim_long = 30000

################################################################################
# Generic Helper Functions
################################################################################
def readWholeFile(path):
   retVal = ""
   try:
      fileId = open(path, 'r')
      retVal = fileId.read()
      fileId.close()
   except:
      pass
   return retVal
   
def writeWholeFile(path, fileText):
   try:
      fileId = open(path, 'w')
      fileId.write(fileText)
      fileId.close()
   except:
      pass

def appendFile(path, fileText):
   try:
      fileId = open(path, 'a')
      fileId.write(fileText)
      fileId.close()
   except:
      pass

def limitLogSize(logFilePath, trimFromTop, logMaxLogLines, logLineToLeaveAfterTrim):
   logFile = readWholeFile(logFilePath)
   lineCount = logFile.count(logNewLine)

   if lineCount > logMaxLogLines:
      if trimFromTop:
         logFile = logNewLine.join(logFile.split(logNewLine)[-logLineToLeaveAfterTrim:])
      else:
         logFile = logNewLine.join(logFile.split(logNewLine)[:logLineToLeaveAfterTrim])
      writeWholeFile(logFilePath, logFile)


def logMsg(printMsg):
   shortTimeFormat = "%H:%M %m/%d"   # 24 hour value
   #shortTimeFormat = "%I:%M%p %m/%d" # 12 hour value with AM/PM
   shortTimeStr = "{}".format(time.strftime(shortTimeFormat))
   longTimeStr  = str(datetime.now())

   logMsg = '[' + longTimeStr + "] " + printMsg
   print(logMsg)
   
   logPath = os.path.splitext(os.path.realpath(__file__))[0] + '.log'
   appendFile(logPath, logMsg + logNewLine)
   limitLogSize(logPath, True, logMaxLogLines_long, logLineToLeaveAfterTrim_long)

def getCurrentTime():
   uptime_seconds = None

   try:
      with open('/proc/uptime', 'r') as f:
          uptime_seconds = float(f.readline().split()[0])
   except:
      logMsg("Failed to get current time")

   return uptime_seconds


################################################################################
# JSON Settings Load Functions
################################################################################
def loadSettingsFromJson():
   global settingsDict
   success = True
   try:
      settingsDict = json.loads(readWholeFile(JSON_PATH))
   except:
      success = False
   return success


################################################################################
# ARP Monitoring Functions
################################################################################
def arpDetector(packet):   
   if packet[ARP].op == 1: # who-has (request)
      if packet[ARP].hwsrc == macAddrTrigger:
         logMsg(packet[ARP].hwsrc) # Just log when the ARP occurs for now.

def runArpMonitor():
   # Set the MAC Address to trigger stuff to do from.
   global settingsDict
   global macAddrTrigger
   macAddrTrigger = settingsDict["DeviceMacAddr"]
   logMsg("MAC Addr Trigger: " + macAddrTrigger)

   while True:
      try:
         sniff(prn=arpDetector, filter="arp", store=0, count=10)
      except:
         pass


################################################################################
# Main Loop
################################################################################
if __name__ == "__main__":
   if loadSettingsFromJson():
      runArpMonitor()
   else:
      logMsg("Failed to read json.")


