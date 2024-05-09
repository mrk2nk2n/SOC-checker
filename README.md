# SOC-checker
An automatic attack system that allows SOC managers to check the team's vigilance

The user will be presented with multiple attack options and a list of IPs to select for execution. Each
selected attack will be saved into a log file in the /var/log directory.

The script will run in 3 main phases:
  1. Network discovery
  2. Attack selection
      a. ARSPOOF
      b. DDOS
      c. Password bruteforce
  3. Attack execution

# Overview of Tools
Tools used: nmap, hiping3, arpspoof, dsniff, hydra

[nmap, hping3] – the nmap & hping3 tools is used to do active host discovery and port scanning.
[arpspoof, dsniff] – the arpspoof tool is used to send forged ARP messages containing incorrect MAC address
information and the dniff tool is used to intercept and eavesdrop on the communication.
[hydra] – the hydra tool was used to attempt login with a list of usernames and passwords on a given service port.

# Possible Enhancements

User could provide their list of passwords and usernames, instead of a prepared list. The estimated time it might take
to run the brute force could be calculated and displayed to the user as well. This allows the user to make an
assessment weighing the scope, time and accuracy.

Multiple host & port scanning tools can be used to further enhance the accuracy of device & port scanning. For
example, using nmap UDP scans as well as the massscan tool. However, this would greatly increase the time taken to
complete the scan.
