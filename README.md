# MITRE_ectf
Secure Framework for updating firmware in an ECU of a self driving car remotely

# Challenge Overview
You’re part of a team designing the next big evolution in
automobiles – a self-driving car. Cars are complex systems
and there are huge number of modules that have to work
together. You’ll be deploying cutting edge algorithms and
will be constantly monitoring the system performance in
the wild thanks to the onboard cellular connection. If any
bugs pop up, or you want to roll out major improvements,
you’ll use this same connection to program each module
with the latest firmware. Done right, this system could save
lives, eliminate traffic, and revolutionize transportation.
However, it’s critically important for the safety of the
occupants that this system works properly, and given the
headlines over the past few years, you have one major
concern: security! Can you imagine if someone was able to fly
a drone over your car and install new firmware1
Or worse, modify your self-driving car over the Internet2

Previous MITRE eCTFs have shown that creating a secure device is harder than it may seem. Even with extensive security
reviews, it’s easy to miss important vulnerabilities. And of course, you’re in a hurry to get your product out to market!
What you really need is a way to send firmware updates to your device so that you can add more features (and fix any
security problems) after shipping. This functionality is typically implemented as a bootloader – special code that runs
every time the device boots. Normally the bootloader will simply turn the execution over to the installed application
firmware but if an update needs to happen, the bootloader will handle it by reprogramming the application firmware
before handing over execution.
Unfortunately, firmware updating doesn’t solve everything and even creates its own set of security concerns because of
the added complexity. Possible threats include:
- Competitors might try to read the firmware in the update (or directly from your device) to steal/reverse-engineer
your algorithms and other intellectual property.
- Hackers might try to modify your firmware update to insert malicious code that causes the device to malfunction
or act as a pivot-point to attack other devices that it connects to.
- Hackers might try to use the update mechanism to install old versions of firmware that have known
vulnerabilities.

# Your challenge is to design and implement a system to support secure firmware distribution for automotive control.
Your system must meet a set of requirements (specified below) and defend against as many attacks as you and the other
teams can think of. You must design and implement a working bootloader as well as a set of supporting tools for things
such as: generating keys, provisioning bootloaders with those keys, protecting firmware updates, and installing those
updates. Once your system is completed, it will be subjected to attacks from the opposing teams, while you get a chance
to attack the designs from the other teams. The purpose of this scenario is to encourage a focus on security for the
embedded system and to allow ALL types of attacks.
