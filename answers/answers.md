# Challenge Answers

## Basic Static Analysis
---

**Question:** What is the SHA256 hash of the sample?

**Answer:** 0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83

![image](https://user-images.githubusercontent.com/5527552/215377299-55306bb5-c68a-408d-8dc6-378d4fe2b3cf.png)

---

**Question:** What architecture is this binary?

**Answer:** This is a 32-bit binary, as identified by VirusTotal website.

![image](https://user-images.githubusercontent.com/5527552/215377516-c9bc51fa-f99e-4ab3-9648-668db80eb7d8.png)

---

**Question:** Are there any results from submitting the SHA256 hash to VirusTotal??

**Answer:** We see that 58 Antivirus engines are able to detect the malware as shown in the VirusTotal. For detailed report you can refer the link https://www.virustotal.com/gui/file/0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83/details

---

**Question:** Describe the results of pulling the strings from this binary. Record and describe any strings that are potentially interesting. Can any interesting information be extracted from the strings?

**Answer:** If we see the output of the Floss/Strings command for the file we see that the whole output as similar to the original Putty program except for one line that is using powershell to run a powershell script as shown:

![image](https://user-images.githubusercontent.com/5527552/215378485-bea1238c-829d-4894-aff5-001c08e4b0e1.png)

---
**Question:** Is it likely that this binary is packed?

**Answer:** If you see the IMAGE_SECTION_HEADER .text section we find that the Virtual Size (Size of the program in memory) is 1847 bytes and the size of the Raw Data (Size of program at rest) is 2048. Thus, the difference between the two sizes is 201 bytes which is significantly smaller as shown:

![image](https://user-images.githubusercontent.com/5527552/215384496-5be35bdd-6135-489b-9c2c-97c4631048a0.png)

Thus, we can say that the malware putty.exe is not packed.

---
## Basic Dynamic Analysis


**Question:** Describe initial detonation. Are there any notable occurances at first detonation? Without internet simulation? With internet simulation?

**Answer:** If we run the putty.exe file it will run as the normal putty program but you will notice a blue screen for a small amount of time as explained by the Incident Response team.

---

**Question:** From the host-based indicators perspective, what is the main payload that is initiated at detonation? What tool can you use to identify this?

**Answer:** if we use procmon to montior the what is happening when we run putty.exe we find that the powershell is running as seen in the static analysis we find the powershell command using the strings command. If we see the tree view we can also conclude that the powershell.exe is running as a child process of putty.exe.

![image](https://user-images.githubusercontent.com/5527552/215385685-86d3dd3f-c8fc-4c89-839a-c50101941aa5.png)

Process Tree to let us know that the powershell is running as child process of putty:

![image](https://user-images.githubusercontent.com/5527552/215385793-10c077c4-c1e3-4bc8-ba31-d44e76808e35.png)

Now as we see in the static analysis as well as the procmon we have found a base64 string in the powershell command let's decode the string as shown


![image](https://user-images.githubusercontent.com/5527552/215386440-035ec651-d255-4c9e-b125-7fec59a4e3d3.png)

We found some compressed garbage value lets take the value and write to a zip file named as powershell.zip as shown:


![image](https://user-images.githubusercontent.com/5527552/215386983-77b64732-42c4-482f-9252-52d043a4d521.png)

Now let's extract the zip file content and see the data we see that it has given us a power shell script in plain text which is connecting to a TCP client "bonus2.corporatebonusapplication.local" and at port 8443 as shown:

![image](https://user-images.githubusercontent.com/5527552/215386734-8f371521-7f07-4aa4-ad7e-a432ba222dff.png)

We can analyze the above code and try to understand the working before deep diving into more analysis.

---

**Question:** What is the callback port number at detonation?

**Answer:** The port is 8443.

![image](https://user-images.githubusercontent.com/5527552/215386912-aa08ace6-698e-45c6-9841-2ba04300f678.png)

---

**Question:** What is the callback protocol at detonation?

**Answer:** The protocol is SSL/TLS as we see the execution though Wireshark in Remnux Linux by "Client Hello" as shown:

![image](https://user-images.githubusercontent.com/5527552/215387473-9b8f8aae-dd04-4168-ace8-5d9c8084d534.png)

and the client running the putty will receive "Server Hello" as shown: 

![image](https://user-images.githubusercontent.com/5527552/215387614-82cce86f-cd4b-470d-8232-cb3b6ecdf7d4.png)

---

**Question:** How can you use host-based telemetry to identify the DNS record, port, and protocol?

**Answer:** We can use the procmon software and add the filters as listed below:

[-] ProcessName contains "putty.exe"
[-] Operations contains "TCP"

---

**Question:** Attempt to get the binary to initiate a shell on the localhost. Does a shell spawn? What is needed for a shell to spawn?

**Answer:** If we try to setup a listener using ncat to port 8443, we will not be able to spawn shell as shown:

![image](https://user-images.githubusercontent.com/5527552/215388524-e27471c7-3427-4356-9e39-1e47d6b5be25.png)

As we see in above screenshot, if we run the putty.exe the shell is not connected to the port 8443. we have to add the host that we found above to the hosts file as shown: 

![image](https://user-images.githubusercontent.com/5527552/215389897-40585dc6-9083-4fa1-880a-4707b6a47071.png)

And we are able to connect but it will provide some garbage value as shown: 

![image](https://user-images.githubusercontent.com/5527552/215390239-35a829b3-6025-48d4-baf4-3099a4d5b8fc.png)


This is because when we decoded the base64 string and analyze the code it will connect only if you provide a valid SSL certificate as shown:

![image](https://user-images.githubusercontent.com/5527552/215388811-8e1b1b48-a58f-42c9-acc0-4d4002c16a78.png) 


Now let's use the command to bypass the SSL as
```
$ ncat -nlvp --ssl 8443
```

After running the command we are able to get the shell as shown:

![image](https://user-images.githubusercontent.com/5527552/215390367-310489f2-50ca-4af9-a8f3-7e9755e5352c.png)












