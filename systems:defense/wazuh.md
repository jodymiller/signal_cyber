**Wazuh on Linux**
Setup:
* Wazuh installed on Ubuntu virtual machine with agents on secondary virtual machine and physical device
* Docker rootless installation

<img width="535" height="110" alt="image" src="https://github.com/user-attachments/assets/46794d19-02f1-49c2-ab43-aa25bd0bd200" />

Learnings:

First, installing a rootless docker setup was not 100% smooth (most things are not) due to unprivileged port errors.  With the intent to keep attack surface at a minimum and this being experimental, I've started with changing the port numbers to be in the unprivileged range and editing the .yml file references to reflect the changed ports. Another future option could be a headless Ubuntu server setup, which I may try next. At one point I had other physical devices attached to Wazuh; however, this is a new start and that is planned for the future. 

Why I like Wazuh...
* First, it is easy to see the vulnuerabilites by agent, and it cleanly classifies these into buckets (critical, high, medium, low, pending). It includes the CVE and you can look up more information straight from the Wazuh dashboard. It also lists the affected packages. 
* Compliance breakdown: PCI DSS, GDPR, NIST 800-53, HIPAA, GPG13, TSC - you can choose your compliance metric and run through the findings. Wazuh will even tell you how to remediate in some cases (do your own checking of course) and I've found it very accurate and highly useful when auditing a system or looking for surfaces to harden. This section has helped me be familiar with each compliance area and discover what type of system requirements exist for it and then you can review events by wazuh-agent or as a whole.

  <img width="462" height="304" alt="image" src="https://github.com/user-attachments/assets/cb4aa94b-b81b-4be6-82a6-f62c35da4996" />

* The CIS benchmarks security configuration assessment is very handy to review general hardening areas. It will give # of passes, # of fails and list all the specific checks and their status (I have some work to do!). This is a great learning opportunity to get to know the ins and outs of a distribution's hardening requirements. I plan to install on a Windows machine and perhaps my macOS to see how those show up too - I'll keep expanding and learning, there is no shortage of new things to discover. 

  <img width="903" height="255" alt="image" src="https://github.com/user-attachments/assets/2f5d28fe-66ac-4fb5-973a-968e719f943d" />
  



