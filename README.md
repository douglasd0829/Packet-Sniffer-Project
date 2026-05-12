# Packet-Sniffer-Project
How to Run the Script
1.	Make sure Python is installed on your system.
2.	Install scapy
3.	Install Npcap and enable WinPcap API-compatible mode
4.	Open Command Prompt as Administrator.
5.	Navigate to the folder where the script is saved.
6.	Run the script using:
python packet_sniffer.py
Notes
•	The script captures live network traffic for 30 seconds.
•	If needed, you can modify the filter in the code:
o	"tcp" → captures only TCP traffic
o	"tcp port 80" → captures HTTP traffic
Output
•	The program prints source IP, destination IP, protocol, and length in real time.
•	After completion, it displays a summary of total packets and protocol counts.
