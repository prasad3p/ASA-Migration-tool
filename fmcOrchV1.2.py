'''
Script provides migration of ASA configs to FMC.
'''

from fmcapi.fmcapi import * #to execute from cli
#from fmcapi import * #to execute from pycharm
import pyclbr
import logging

#################################################### Variables #########################################################

#Config files paths info
logfile = "logFile.log"
configFile = "configFile.txt"

#Logger configuration
logger = logging.getLogger('logFile')
hdlr = logging.FileHandler(logfile)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)
groupMap = {}

############################################## Defns of supporting functions ###########################################

#Returns a list of all the available objects defined in the file api_objects.py
def getAvailabeObjects():

    objectList = []
    module_info = pyclbr.readmodule('api_objects')

    for item in module_info.values():
        if(item.name != "APIClassTemplate"):
            objectList.append(item.name)

    #logger.info("List of available objects imported in the code.")
    return objectList

#Prints available objects in api_objects.py
def printAvailableObjects(objectList):
    num = 1
    print("Available objects:\n")
    for obj in objectList:
        print("%d. %s"%(num,obj))
        num +=1

def maskConvert(mask):
    maskSplits = mask.split(".")
    sum = 0
    for x in maskSplits:
        sum += bin(int(x)).count("1")

    return sum

def doPost():

    myfile = open(configFile, "r")
    line = myfile.readline()
    needNext = 0

    while 1:

        line = line.strip()
        #print ("Migrating.. "+line)

        if (line.startswith("#")) :
            needNext = 1

        elif(line.startswith("object network")):

            try:
                nameSplit = line.split(" ")
                objname = nameSplit[2].strip() #name of host/subnet
                line = myfile.readline()
                objSplits = line.split(" ")
                id = objSplits[1].strip() #id is either host or subnet

            except:
                logger.error("Configuration file error in line: "+line.strip())
                exit()

            if id == "host":#if id is host
                ip = objSplits[2].strip()
                iphost1 = IPHost(fmc=fmc1, name=objname, value=ip)
                iphost1.post()
                del iphost1

            else:           #if id is subnet
                value = objSplits[2].strip()#ip address
                preMask = objSplits[3].strip() #mask in x.x.x.x format
                mask = maskConvert(preMask)  # convert x.x.x.x to /y format
                ip = value + "/" + str(mask)  # combine ip and mask
                ipnet1 = IPNetwork(fmc=fmc1, name=objname, value=ip)
                ipnet1.post()
                del ipnet1

            needNext=1
            #line = myfile.readline()

        elif(line.startswith("object-group network")):

            try:
                nameSplit = line.split(" ")
                objname = nameSplit[2].strip()#Name of the group
            except:
                logger.error("Configuration file error in line: "+ line.strip())
                exit()

            obj1 = NetworkGroup(fmc=fmc1, name=objname)

            #Create list of objects in this group
            #To be used in ACL creation.
            objList = []
            groupMap [objname] = objList

            line = myfile.readline() #read next line

            while line.startswith(" "): #read the file until you encounter next set of configs.

                entrySplits = line.split(" ")

                if entrySplits[1].strip() == "group-object":
                    logger.error("group-object configuration under " +objname+ " is NOT SUPPORTED in line: "+line.strip())
                    line = myfile.readline()
                    break

                subObjName = entrySplits[3].strip()
                objList.append(subObjName)

                obj1.named_networks(action='add', name=subObjName)
                line = myfile.readline()

            needNext = 0
            obj1.post()
            del obj1

        elif(line.startswith("object service")):

            try:
                nameSplit = line.split(" ")
                objname = nameSplit[2].strip()#name of service
                line = myfile.readline()# go to next line
                detailsSplit = line.split(" ")
                protocol = detailsSplit[2].strip() #get protocol
                portNumber = detailsSplit[5].strip() #get portnumber
            except:
                logger.error("Object service configuration file error in line: "+ line.strip())
                exit()


            pport1 = ProtocolPort(fmc=fmc1, name=objname, port=portNumber, protocol=protocol)
            pport1.post()
            del pport1

            needNext = 1

        elif (line.startswith("object-group service")):

            try:
                nameSplit = line.split(" ")
                objname = nameSplit[2].strip()  # Name of the group
            except:
                logger.error("MIGRATION NOT SUPPORTED in line: " + line.strip())
                exit()

            obj1 = ProtocolPortObjectGroups(fmc=fmc1, name=objname)
            line = myfile.readline()

            while line.startswith(" "):  # read the file until you encounter next set of configs.

                if line.startswith(" service-object"):

                    portSplits = line.split(" ")

                    if portSplits[2] != "object":
                        logger.error("MIGRATION NOT SUPPORTED in line: " + line)
                    else:
                        portName = portSplits[3].strip()
                        obj1.named_ProtocolPortObjectGroups(action='add',name=portName)

                else:
                    logger.error("MIGRATION NOT SUPPORTED in line: " + line.strip())

                line = myfile.readline()

            needNext = 0
            obj1.post()
            del obj1

        elif (line.startswith("access-list")):

            try:
                lineSplits = line.split(" ")
                policyName = lineSplits[1].strip()
                temp = policyName
            except:
                logger.error("Access list configuration file error in line: "+ line.strip())
                exit()

            try:
                if(lineSplits[2].strip() == "global" or lineSplits[2].strip() == "in" or lineSplits[2].strip() == "out"):
                    logger.error("Configuration NOT SUPPORTED in line: "+line.strip())
                    line = myfile.readline()
                    continue
            except:
                logger.error("Configuration file error. Unable to post access-list in line: "+line.strip())
                exit()

            acp1 = AccessControlPolicy(fmc=fmc1, name=policyName)
            acp1.post()
            time.sleep(1)
            rulNum = 1
            portNum = 1

            while True:

                lineSplits = line.split(" ")
                acprule1 = ACPRule(fmc=fmc1, acp_name=acp1.name)
                acprule1.name = acp1.name + "_Rule"+str(rulNum)
                rulNum = rulNum+1
                map = {"permit":"ALLOW", "deny":"BLOCK"}
                protocolList = ["tcp","udp","icmp","ip","object-group"]

                try:
                    if(lineSplits[3].strip() == "deny" or lineSplits[3].strip() == "permit"):

                        acprule1.action = map[lineSplits[3].strip()]

                        if(lineSplits[4].strip() not in protocolList):

                            logger.warning("Configuration NOT SUPPORTED in line: "+line.strip())
                            line = myfile.readline()
                            if (line.startswith("access-list")):
                                spl = line.split(" ")
                                policyName1 = spl[1].strip()
                                if (policyName1 != temp):
                                    break
                                else:
                                    continue
                            else:
                                break

                        try:

                            portVal = lineSplits[10].strip()

                            if line.__contains__(" range "):
                                raise Exception ("Port range not supported.")

                            if portVal.isnumeric():
                                pport1 = ProtocolPort(fmc=fmc1, name="Port_"+lineSplits[4].strip() +"_"+portVal, port=portVal, protocol=lineSplits[4].strip() )
                                portNum = portNum+1
                                pport1.post()
                                time.sleep(2)
                                acprule1.destination_port(action='add', name=pport1.name)
                            else:
                                raise Exception ("Configure port manually")

                        except:
                            logger.warning("No single port configured for the rule: "+acprule1.name+ " in line:"+line.strip())

                        #If config contains port gourp adjust source and destination hosts/network position indices.
                        if lineSplits[4].strip() == "object-group":
                            srcIndex = 7
                            dstIndex = 9
                            acprule1.named_ProtocolPortObjectGroups(action='add',name = lineSplits[5].strip())
                        else:
                            srcIndex = 6
                            dstIndex = 8

                        try:

                            if(lineSplits[5].strip() == "object-group"):

                                tempList = groupMap [lineSplits[srcIndex].strip()]
                                for i in tempList:
                                    acprule1.source_network(action='add',name=i)

                            else:
                                acprule1.source_network(action='add',name=lineSplits[srcIndex].strip())

                        except:
                            logger.warning("No source network configured for the rule: "+acprule1.name+" in line: "+line.strip())

                        try:

                            if(lineSplits[7].strip() == "object-group"):

                                tempList = groupMap [lineSplits[dstIndex].strip()]
                                for i in tempList:
                                    acprule1.destination_network(action='add',name=i)
                            else:
                                acprule1.destination_network(action='add',name=lineSplits[dstIndex].strip())

                        except:
                            logger.warning("No destination network configured for the rule: "+acprule1.name+" in line: "+line.strip())

                        if(lineSplits[-1].strip() == "inactive"):
                            acprule1.enabled = False

                        if (lineSplits[-1].strip() == "log" or lineSplits[-2].strip() == "log"):
                            acprule1.sendEventsToFMC = True
                        time.sleep(10)
                        acprule1.post()
                        time.sleep(1)

                except:
                    logger.warning("No rule configured under policy: "+ acp1.name+" in line: "+line.strip())

                line = myfile.readline()
                if(line.startswith("access-list")):
                    spl = line.split(" ")
                    policyName1 = spl[1].strip()
                    if(policyName1 != temp):
                        needNext = 0
                        break
                else:
                    needNext = 0
                    break

        else:
            logger.error("Configuration NOT SUPPORTED in line: "+line.strip())
            needNext = 1

        #fmcapi yet to be developed for service groups.
        #elif(line.startswith("object-group service")):
        '''
        elif(line.startswith("access-list")):

            nameSplit =line.split(" ")
            policyName = nameSplit[1].strip()
            acp1 = AccessControlPolicy(fmc=fmc1, name=policyName)
            acp1.post()

            if nameSplit[2] == "extended" or nameSplit[2] =="standard":
        '''
        if needNext == 1:
            line = myfile.readline()
            needNext = 0

        if not line:
            print("Please see the logfile "+logfile+" for error messages.")
            exit()

####################################################### Main ###########################################################

#Accept user inputs and validate
ipaddress = input("Enter IP address of FMC:")
username = input("Username:")
password = input("Password:")

with FMC(host= ipaddress , username=username , password=password) as fmc1:

    logger.info("FMC Connection was successful.")
    doPost()
    exit()












