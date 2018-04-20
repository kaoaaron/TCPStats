'''
CSC 361 Assignment 2
Author: Aaron Kao
---------------------
Purpose:
This program exists in order to determine
1) Details about Complete TCP Connections (specified by at least 1 syn and 1 fin)
2) General Statistics of the TCP Connections
'''

Files:
TCPstats.py
readme.txt

Adknowledgements: 
Thanks to the students of the CSC 361 class on asking questions to fully specify and define the assignment.
I started this assignment fairly late, and if the students did not ask questions, I would have had to make decisions.

Requirements:
Python 2.7 was used to construct this program. Python 3 will NOT work.

How to Run Program:

First off, the DPKT library needs to be installed. To install this library, enter pip install dpkt in the terminal

To run the program, only one parameter can be included. A command, such as the following is valid

python TCPstats.py example.cap

Invalid commands include the following

python3 TCPstats.py example.cap
python SmartClient.py example.cap dolphins.cap

