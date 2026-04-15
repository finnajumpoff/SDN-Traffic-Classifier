# SDN Mininet - Traffic Classification System

## Problem Statement
The goal of this project is to implement an SDN-based solution using Mininet and the POX controller to demonstrate controller-switch interaction and flow rule design. The system classifies network traffic into ICMP, TCP, and UDP protocols and applies explicit match-action rules.

## Setup & Execution Steps
1. Start the POX controller: `python3 pox.py traffic_classifier`
2. Start the Mininet topology: `sudo mn --controller remote,ip=127.0.0.1 --topo single,3`
3. Test connectivity: `pingall`
4. Test TCP throughput: `iperf h1 h2`
5. Test UDP throughput: `h2 iperf -u -s &` and `h1 iperf -u -c 10.0.0.2 -b 10M`

## Expected Output & Proof of Execution
