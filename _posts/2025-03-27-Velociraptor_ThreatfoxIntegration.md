---
layout: post
title: "Velociraptor and Threatfox"
date: 2025-03-27
author: Cory Keller
---

If you're using an edr tool you might find this a bit redundant but the facts are not every organization is on the same maturity level as you are, this is aimed to fill a gap and enable a threat hunt against the data aggregated. Some organizations are budget constrained and need something that doesn't break the bank or your annual budget. For this we will utilize sysmon and velociraptor. 

![Obligatory Clever Girl](https://www.google.com/url?sa=i&url=https%3A%2F%2Fwww.jimchines.com%2F2018%2F05%2Featen-by-velociraptors%2Fclevergirl%2F&psig=AOvVaw0QbIa4rf5kSLs9ZF_UebtL&ust=1743211171084000&source=images&cd=vfe&opi=89978449&ved=0CBAQjRxqFwoTCJCZ8-bNq4wDFQAAAAAdAAAAABAE)

In incident response it is common to check connections to determine if a user actually connected to an malicious IP/host. Not every organization has access to a network security monitoring stack to get items like Zeek logs. However, one thing that would be far easier to implement or that is already implemented in the organization is sysmon. For those unfamiliar "System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log." ([Sysmon Documentation][sysmon-docs], 2025). 

The super power I think about sysmon is when you don't have access to an USEFUL EDR tool, is the Event ID 3. Event ID 3 will give you many useful event items about the connection that was established with the remote server, but why I think it is a super power to enable this Event is the ability to see the file name that established the connection (full event objects here: [Sysmon Event ID 3][event-id-3]). If you wish to access these events you also have to enable that event in your sysmon configuration file during installation. To see how to install sysmon and access a very good prebuilt config file visit [Swift on Security Sysmon Configuration and Installation][swift-config].

Threat intelligence that is free and limitless in queries is really hard to come by. However, Threatfox [Threatfox][threatfox] is a free IOC database that can be used for our queries to come. We will utilize a Threatfox velociraptor artifact I created([Velociraptor Artifact Submission Director Fusion][dfusion-tf]) used for Server enrichment of logs, to perform hunts with velociraptor against our event logs on clients and compare against IOCs in ThreatFox. 

I did pull my submission as others have submitted something similar and I don't want to hand over duplicates. However, still useful and a good opportunity to show case how to add your own artifact to Velociraptor and help you with your own ideas for artifacts in velociraptor.

```
name: Server.Enrichment.ThreatFox
description: |
   Query ThreatFox for IOCs. Idea was to use it to check if a hash, IP address or domain is in a list of known
   
   To learn more about ThreatFox, see: https://threatfox.abuse.ch/
   
   SHOUTOUT THANKS to mike.cohen and predictiple on VQL discord getting the double foreach explained to me. Appreciate it
   
   This artifact is intended to be called to check if w/e indicators you're checking are inside ThreatFox IOCs withing the last 24 hours. 
     Ex.
       `SELECT * from Artifact.Server.Enrichment.ThreatFox()
       
     Ex. Use in a hunt...
     '''
    LET TFData <= SELECT ioc, ioc_type FROM Artifact.Server.Enrichment.ThreatFox()
    LET IpConns = SELECT System.Computer AS Computer, EventData.DestinationIp AS DestIp, EventData.DestinationHostname AS DestHost FROM parse_evtx(filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx") WHERE System.EventID.Value = 3 AND DestIp != '34.36.95.252'
    SELECT * FROM foreach(row=IpConns, query={SELECT str(str=ioc) AS IOC, ioc_type, str(str=DestIp) AS DstIP, DestHost FROM foreach(row=TFData)}) WHERE IOC =~ DstIP OR IOC =~ DestHost
        '''
# Can be CLIENT, CLIENT_EVENT, SERVER, SERVER_EVENT
type: SERVER

parameters:
   - name: Query
     default:
   - name: Days
     default:


sources:
    - query: |
        LET TFSubmission <= 
            SELECT parse_json(data=Content).data AS Records
            FROM http_client(url="https://threatfox-api.abuse.ch/api/v1/",
                           method="POST",
                           data='{"query": "get_iocs", "days": 1}')
        
        SELECT ioc, ioc_type
        FROM foreach(row=TFSubmission.Records, query={SELECT * FROM foreach(row=_value)})
```

Add this Artifact to your velociraptor instance:

### Go to Artifacts Section

![Artifacts Section](/assets/images/view-artifacts.png)

### Add the Artifact

![Add the artifact here](/assets/images/addartifact.png)

### Corect Appearance in GUI

![Artifact Appearance in VC GUI](/assets/images/threatfox-artifact.png)

This yaml artifact will create a SERVER artifact to aid hunts when called in the Hunts section. Once that is added moved to the Notebooks section:

![Create a notebopl ](/assets/images/vc-notebooks.png)

### VQL Hunt Notebook Syntax

Now after you create a notebook and a VQL cell: paste in this hunt.

```
LET TFData <= SELECT ioc, ioc_type FROM Artifact.Server.Enrichment.ThreatFox()
LET IpConns = SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS Time, System.Computer AS Computer, EventData.DestinationIp AS DestIp, EventData.DestinationHostname As DestHost FROM parse_evtx(filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx") WHERE System.EventID.Value = 3 AND DestIp != '34.36.95.252' 

SELECT * FROM foreach(row=IpConns, query={SELECT Time, str(str=ioc) AS IOC, ioc_type, str(str=DestIp) AS DstIP, str(str=DestHost) As DstHost FROM foreach(row=TFData)}) WHERE IOC =~ DstIP OR DstHost =~ IOC
```

This SQL like syntax is called VQL. It allows you to interface with velociraptor to query your logs in question like a database. That is a over generalization, but it is not a blog about how Velociraptor works. 

This hunt will create two variables TFData which calls the artifact we just created to pull the TFData and IPConns variable which is a SELECT statement to pull Event ID 3 event logs from the sysmon evtx file. It also filters out the IP address "34.36.95.252" which is a google cloud ip that was noisy in my logs for testing, so I removed it from the results.

Then the final part of the hunt checks if the IOCS exist inside the Event ID 3 event logs parsed from the machine(s) queried. If you have hits expect output from the notebook as seen here:

![Threatfox Hit](/assets/images/threatfox-hit.png)

Ohhh nooo, I really didn't plan this... Now we see a hit to the Threatfox IOC database we can now go to our event logs and look for the powershell.exe hit. Additionally, you can modify that query to return the relevant information you'd want for triaging. However, I was limited to space to generate a useful screenshot. In the real world you can make this yours and use it as you need to use it. 

If you went to the lgo data you would see:

![Event Log of IOC Match](/assets/images/eventlogdata.png)

### Successful Hunt!

Now that you see how this works, scaling is the next step. You would only want to call the TFData API call once, so you are not making repeat requests to the API. But then you can have this as a hunt in velociraptor to check all your clients sysmon logs, which would take some additional tweaking from our current setup discussed in this blog but easily doable. 

[sysmon-docs]: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
[event-id-3]: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?source=Sysmon&eventID=3
[swift-config]:https://github.com/SwiftOnSecurity/sysmon-config
[velociraptor]: https://docs.velociraptor.app/
[threatfox]: https://threatfox.abuse.ch/browse/
[dfusion-tf]: https://github.com/Velocidex/velociraptor-docs/pull/806/commits/04a11ec401203729fb989e3c6dc9556245818571
