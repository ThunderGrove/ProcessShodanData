import json

lines=[]
#shodan download --limit 938 stofa has_vuln:verified org:Stofa
#Each device from the search result from the CLI-API tool from Shodan gets thier own JSON array so we need to split the JSON file up and parse each line as an array
with open('stofa.json') as file:
    for count, line in enumerate(file):
        lines.append(json.loads(line.strip()))
        pass

print('Lines in JSON file:', count+1)

#ipcount=dict()
#currententry=1
#ipcount[lines[0]['ip_str']]=1
#while currententry<count+1:
#    internalcount=1
#    internalentry=0
#    while internalentry<currententry:
#        if lines[internalentry]['ip_str'].__eq__(lines[currententry]['ip_str']):
#            internalcount=internalcount+1
#        internalentry=internalentry+1
#        ipcount[lines[currententry]['ip_str']]=internalcount
#    currententry=currententry+1
#print(ipcount)

for result in lines:
    print(result['ip_str'])
    for resultOne in result['vulns']:
        print(result['vulns'][resultOne]['cvss'])

cves=[]
currententry=0
while currententry<count+1:
    if len(lines[currententry]['opts'])!=0:#When printing out an empty opts out in CLI it will appeare as the content is "{}" but it is at zero character string.
        if "vulns" in lines[currententry]['opts']:
            cves.append(lines[currententry]['opts'])
    currententry=currententry+1

cvescounter=dict()
currententry=0
while currententry<len(cves):
    if len(cves[currententry]['vulns'])!=0:
        intenalcount=0
        while intenalcount<len(cves[currententry]['vulns']):
            #print(cves[currententry]['vulns'][intenalcount])
            if cves[currententry]['vulns'][intenalcount] in cvescounter:
                cvescounter[cves[currententry]['vulns'][intenalcount]]=cvescounter[cves[currententry]['vulns'][intenalcount]]+1
            else:
                cvescounter[cves[currententry]['vulns'][intenalcount]]=1
            intenalcount=intenalcount+1
        #print(cves[currententry]['vulns'])
    currententry=currententry+1
#print(cvescounter)
