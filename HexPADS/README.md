# HexPADS, a host-based, Performance-counter-based Attack Detection System

Current systems are under constant attack from many different sources. Both
local and remote attackers try to escalate their privileges to exfiltrate data,
to escalate privileges, or to gain arbitrary code execution. While inline
defense mechanisms like DEP, ASLR, or stack canaries are important, they have a
local, program centric view and miss some attacks. Intrusion Detection Systems
(IDS) use runtime monitors to measure current state and behaviour of the system
to detect an attack orthogonal to active defenses.

Attacks change the execution behavior of a system. Our attack detection system
HexPADS detects attacks through divergences from normal behavior using attack
signatures. HexPADS collects information from the operating system on runtime
performance metrics with measurements from hardware performance counters for
individual processes. Cache behavior is a strong indicator of ongoing attacks
like rowhammer, side channels, covert channels, or CAIN attacks.  Collecting
performance metrics across all running processes allows the correlation and
detection of these attacks. In addition, HexPADS can mitigate the attacks or
significantly reduce their effectiveness with negligible overhead to benign
processes.

See the paper for more details: http://hexhive.github.io/publications


## Author

Mathias Payer <mathias.payer@nebelwelt.net>


## Installation

Adjust src/hexpads.h to select a specific mitigation and then ''make'' in the 
src/ directory. Compilation was tested with clang and gcc on x86-64 Ubuntu
15.04, and Ubuntu 15.10, and Debian 8.0 Jessie. The current Makefile is
configured for clang 3.6 but gcc and other clang versions should produce the
same results. The source code relies on an installed build system (apt-get
install build-essential llvm).


## Test

Keep ./src/hexpads running in a terminal. In a second terminal, enter the
./test directory and run any of the following attacks:
```
$ ./test.sh CAIN
$ ./test.sh C6
$ ./test.sh CSC
$ ./test.sh rowhammer
```

CAIN was developed by Antonio Barresi, C6 by Clementine Maurice, CSC by Daniel
Grauss, and rowhammer by P0 at Google. The source code of their software can be
found in their repositories. The test directory contains pre-compiled versions
for x86-64 on Ubuntu 15.10.

Depending on the mitigation you have selected you need to take special measures
to kill the test process. E.g., with SIGSTOP you have to kill the corresponding
process from another terminal as it was stopped on the current screen.


## Notes

Performance monitoring is generally not available inside virtual machines,
therefore HexPADS must be run on bare metal.
