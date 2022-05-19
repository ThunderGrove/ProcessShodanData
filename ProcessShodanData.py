import json

lines=[]
#shodan download --limit 938 stofa has_vuln:verified org:Stofa
#Each device from the search result from the CLI-API tool from Shodan gets thier own JSON array so we need to split the JSON file up and parse each line as an array
with open('stofa.json') as file:
    for count, line in enumerate(file):
        lines.append(json.loads(line.strip()))
        pass

#print('Lines in JSON file:', count+1)

#Proberly starts a HTML5 file
html='<!DOCTYPE html><html><head><title>Shodan data results</title><style>body{background:#333;color:#eee;}div{float:left;width:1000px;}div div{width:300px;}td{padding:2px;}</style></head><body><div>'

#Creates a table of all IPs with all vulnerabilities with thier CVE kode and the CVSS score the CVE kode have received
html=html+'<h2>List of all IPs with all vulnerabilities and thier CVE kode</h2><table><tr><td>IP</td><td>CVE</td><td>CVSS</td></tr>'
for result in lines:
    first=True
    for vuln in result['vulns']:
        if first:
            html=html+'<tr><td>'+result['ip_str']+'</td><td>'+vuln+'</td><td>'+str(result['vulns'][vuln]['cvss'])+'</td></tr>'
            first=False
        else:
            html=html+'<tr><td></td><td>'+vuln+'</td><td>'+str(result['vulns'][vuln]['cvss'])+'</td></tr>'
html=html+'</table></div>'

#Creates a table with all IPs with the vulnerability with the highest CVSS score
html=html+'<div><h2>List of all IPs with the vulnerability with the highest CVSS score</h2><table><tr><td>IP</td><td>CVE</td><td>CVSS</td></tr>'
for result in lines:
    cve=""
    cvss=0.0
    first=True
    #Goes through all vulnerabilities to find the CVE with the highest CVSS score. Thier are a Python function to sort dictionaries but the sort functions does not work with stings as key.
    for vuln in result['vulns']:
        if float(result['vulns'][vuln]['cvss'])>cvss:
            cvss=float(result['vulns'][vuln]['cvss'])
            cve=vuln
    html=html+'<tr><td>'+result['ip_str']+'</td><td>'+cve+'</td><td>'+str(cvss)+'</td></tr>'

html=html+'</table></div>'

#Creates a table that list how many times a given CVE appears in the dataset.
html=html+'<div><h2>List of all CVEs in processed datasat and how many time they appears in with the dataset</h2><span>Lines in JSON file:'+str((count+1))+'</span><br/><br/><table><tr><td>CVE</td><td>Times</td></tr>'
cvedict=dict()
#Count number of times each vulnerability appears.
for result in lines:
    for vuln in result['vulns']:
        if vuln in cvedict:
            cvedict[vuln]=cvedict[vuln]+1
        else:
            cvedict[vuln]=1
#Lists the count.
for cve in cvedict:
    html=html+'<tr><td>'+cve+'</td><td>'+str(cvedict[cve])+'</td></tr>'
html=html+'</table>'

#Proberly ends a HTML file
html=html+'</div></table></div>'

#Writes result to a HTML file
file=open("result.html","w")
file.write(html)
