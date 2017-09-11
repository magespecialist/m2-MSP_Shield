# MSP Shield

MSP Shield is the **most powerful and most effective protection** against malicious user in the MSP Security Suite.<br />
It is a fully featured **Intrusion Detection** and **Intrusion Prevention** System for PHP.<br />
<br />
MSP Shield is capable of detecting a wide number of **hack attempts** and protect your Magento 2 from a wide number
of potential **code vulnerabilities**.<br />
<br />
You will have an high level of protection against 0-day vulnerabilities, code injections, exploit testing and other known attack patterns.<br />
<br />
**NOTE:** Installing this module does not exempt you from keeping your system **up to date**.<br />
<br />

> Member of **MSP Security Suite**
>
> See: https://github.com/magespecialist/m2-MSP_Security_Suite

## Installing on Magento2:

**1. Install using composer**

From command line: 

```
composer require msp/shield
php bin/magento setup:upgrade
```

**2. Enable and configure from your Magento backend config**

<img src="https://raw.githubusercontent.com/magespecialist/m2-MSP_Shield/master/screenshots/config.png" />

NOTE: Enabling this module for backend can trigger false positives, we strongly suggest to keep it enabled only for
 frontend and to protect your backend with https://github.com/magespecialist/m2-MSP_AdminRestriction module .

## How to test it

MSP Shield can detect a wide number of PHP attack patterns and attack attempts.<br />
You can test it in any Magento 2 form by typing a malicious request.<br />
<br />
For example you can try typing `; drop database magento` in any form.<br />
<br />
This will simulate a **SQL injection attack**. Magento is already protected against this kind of attack, but you can try it
to verify the correct configuration of MSP Shield.

<img src="https://raw.githubusercontent.com/magespecialist/m2-MSP_Shield/master/screenshots/injection_attempt.png" />

If you correctly installed and configured MSP Shield, an emergency stop screen will appear.

## Hack Attempt detected (with stealth mode disabled)

<img src="https://raw.githubusercontent.com/magespecialist/m2-MSP_Shield/master/screenshots/detected.png" />

## Hack Attempt detected (with stealth mode enabled)

<img src="https://raw.githubusercontent.com/magespecialist/m2-MSP_Shield/master/screenshots/detected_stealth.png" />

## Logged entries ##

You can browse and search logged events for blocked or non-blocked requests in **System > MSP Security Suite > Events Report**.
