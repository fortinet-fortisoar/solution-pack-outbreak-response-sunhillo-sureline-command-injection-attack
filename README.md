# Release Information 

- **Version**: 1.0.0 
- **Certified**: No 
- **Publisher**: Fortinet 
- **Compatible Version**: FortiSOAR 7.4.0 and later 

# Overview 

FortiGuard Labs continues to see targeted attacks affecting a vulnerability, identified as CVE-2021-36380, that enables a malicious actor to establish an interactive conduit, gaining command over the targeted system and potentially achieving full system compromise. 

 The **Outbreak Response - Sunhillo SureLine Command Injection Attack** solution pack works with the Threat Hunt rules in [Outbreak Response Framework](https://github.com/fortinet-fortisoar/solution-pack-outbreak-response-framework/blob/release/1.0.0/README.md#threat-hunt-rules) solution pack to conduct hunts that identify and help investigate potential Indicators of Compromise (IOCs) associated with this vulnerability within operational environments of *FortiSIEM*, *FortiAnalyzer*, *QRadar*, *Splunk*, and *Azure Log Analytics*.

 The [FortiGuard Outbreak Page](https://www.fortiguard.com/outbreak-alert/sunhillo-sureline-attack) contains information about the outbreak alert **Outbreak Response - Sunhillo SureLine Command Injection Attack**. 

## Background: 

According to the Sunhillo company website, it handles all life-cycle aspects of surveillance data distribution systems for the Federal Aviation Administration, US Military, civil aviation authorities, and national defense organizations across the globe. The (CVE-2021-36380) vulnerability exists in the Sureline software due to improper input validation in the "ipAddr" and "dnsAddr" parameters which allows an attacker to manipulate the resulting command by injecting valid OS command input allowing the establishment of an interactive remote shell session. 

## Announced: 

July 22, 2021: Sunhillo published the security bulletin and a patch notice. 
https://www.sunhillo.com/fb011/

Oct 09, 2023: FortiGuard Labs team observed that the IZ1H9 Mirai-based DDoS campaign targeted Sunhillo SureLine and released a detailed analysis.
https://www.fortinet.com/blog/threat-research/Iz1h9-campaign-enhances-arsenal-with-scores-of-exploits 

## Latest Developments: 

Mar 5, 2024: Attacks in the wild have been reported by CISA - adding CVE-2021-36380 to the Known exploited vulnerabilities catalog.
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Fortinet has existing IPS signatures to proactively protect our customers for the attack attempts, however it is recommened to apply the patch as provided by the vendor if not already done. Since Janurary of this year, Fortiguard IPS signature is intercepting almost double the average attack attempts. 

# Next Steps
 | [Installation](./docs/setup.md#installation) | [Configuration](./docs/setup.md#configuration) | [Usage](./docs/usage.md) | [Contents](./docs/contents.md) | 
 |--------------------------------------------|----------------------------------------------|------------------------|------------------------------|