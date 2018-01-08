# F5 BIG-IP Security Cheatsheet

This document describes common misconfigurations of F5 Networks BIG-IP systems and their elimination. Some settings can be different for different BIG-IP versions.

## Slides
* [F5 BIG-IP Misconfigurations (Zero Nights 2016).](f5-bigip-zn2016.pdf)

## Table of Contents
- [Summary](#summary)
- [Common Misconfigurations](#common-misconfigurations)
  - [Persistence Cookie Information Leakage](#persistence-cookie-information-leakage)
  - [HTTP Server Header Information Leakage](#http-server-header-information-leakage)
  - [Access to Management Interface from Internet](#access-to-management-interface-from-internet)
  - [HTTP Host Header Insufficient Validation](#http-host-header-insufficient-validation)
  - [Mass Enumeration using Search Engines](#mass-enumeration-using-search-engines)
  - [APM Session Exhaustion DoS attack](#apm-session-exhaustion-dos-attack)
  - [APM Brute Force Passwords Attack](#apm-brute-force-passwords-attack)
- [Getting an A-grade on Qualys SSL Labs](#getting-an-a-grade-on-qualys-ssl-labs)
  - [Enabling TLS Fallback SCSV extension](#enabling-tls-fallback-scsv-extension)
  - [Enabling Strict Transport Security](#enabling-strict-transport-security)
  - [Prioritizing PFS ciphersuites](#prioritizing-pfs-ciphersuites)
  - [Disabling SSLv3 on management interface](#disabling-sslv3-on-management-interface)
- [Securing Administrative Access](#securing-administrative-access)
  - [SSH](#ssh) 
  - [Legal Notification Banner](#legal-notification-banner)
  - [Inactive Administrative Session Timeout](#inactive-administrative-session-timeout)
  - [Connection Settings](#connection-settings)
  - [Password Policy for Administrative Users](#password-policy-for-administrative-user)
- [Vulnerability Search](#vulnerability-search)
 
## Summary
The BIG-IP family of products offers the application intelligence network managers need to ensure applications are fast, secure and available.
All BIG-IP products share a common underlying architecture, F5's Traffic Management Operating System (TMOS), which provides unified intelligence, flexibility and programmability.
Together, BIG-IP's powerful platforms, advanced modules, and centralized management system make up the most comprehensive set of application delivery tools in the industry.

BIG-IP devices work on a modular system, which enables to add new functions as necessary to quickly adapt to changing application and business needs.
The following modules are currently available for the BIG-IP systems:
* Application Acceleration Manager (AAM)
* Advanced Firewall Manager (AFM)
* Access Policy Manager (APM)
* Application Security Manger (ASM)
* Global Traffic Manager (GTM)
* Link Controller (LC)
* Local Traffic Manager (LTM)
* Protocol Security Module (PSM)

## Common Misconfigurations

### Persistence Cookie Information Leakage

#### Description

An attacker can get some sensitive information about internal network stored in BIG-IP LTM persistence cookie.  

To implement persistence sessions BIG-IP system inserts a cookie into the HTTP response,
which well-behaved clients include in subsequent HTTP requests for the host name until the cookie expires.
The cookie name, by default, contains `BIGipServer` string and configured name of virtual servers pool. The cookie is set to expire based on the time-out configured in the persistence profile.
The cookie value contains the encoded IP address and port of the destination server in one of the following [format](https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html):
* IPv4 pool members: `BIGipServer<pool name> = <The encoded server IP>.<The encoded server port>.0000`
* IPv6 pool members: `BIGipServer<pool name> = vi<The full hexadecimal IPv6 address>.<The port number calculated in the same way as for IPv4 pool members>`
* IPv4 pool members in non-default route domains: `BIGipServer<pool name> = rd<The route domain ID>o00000000000000000000ffff<The hexadecimal representation of the IP address of the pool member>o<The port number of the pool member>`
* IPv6 pool members in non-default route domains: `BIGipServer<pool name> = rd<The route domain ID>o<The full hexadecimal IPv6 address>o<The port number of the pool member>`

Examples:
* `BIGipServer~DMZ_V101~web_443=1677787402.36895.0000`
* `BIGipServer~CORP_DC1=vi20010112000000000000000000000030.20480`
* `BIGipServer~EE_ORACLE=rd5o00000000000000000000ffffc0000201o80`
* `BIGipServer~ES~test.example.com=rd3o20010112000000000000000000000030o80`

After decoding of the BIG-IP persistence cookie value an attacker can get an internal IP address, port number, and routed domain for backend servers.
In some cases an attacker can also get sensitive informaion recorded in `<pool_name>` suffix of the cookie name.
For example, if an administrator give meaningful name to server pool (e.g., Sharepoint, 10.1.1.0, AD_prod) an attacker will get some additional information about network. Besides, an attacker detects that BIG-IP system is used in network infrustructure.

#### Testing

1. Run intercepting proxy or traffic intercepting browser plug-in, trap all responses where a cookie is set by the web application.
2. If possible, log in to web application and inspect cookies.
3. Find a cookie with a name beginning with BIGipServer string or with a value that has one of the formats above (e.g., `1677787402.36895.0000` for IPv4 pool members scheme).
4. Try to decode this value using available tools (see below).
5. Inspect suffix of BIGipServer cookie name and verify that it does not contain any sensitive information about network infrustructure.

The following example shows a GET request to BIG-IP and its response:
 ```
GET /app HTTP/1.1
Host: example.com
 ```
 ```
HTTP/1.1 200 OK
Set-Cookie: BIGipServerOldOWASSL=110536896.20480.0000; path=/
 ```
Here we can see that backend's pool has the meaningful name OldOWASSL and includes backend server 192.168.150.6:80

#### Tools
* [Metasploit Framework Module](http://www.rapid7.com/db/modules/auxiliary/gather/f5_bigip_cookie_disclosure)
* [Burp Suite Extension](http://professionallyevil.com/subdomains/extensions/Burp-F5Cookie-Extension.py.zip)
* [BeEF Module](https://github.com/beefproject/beef/tree/master/modules/network/ADC/f5_bigip_cookie_disclosure)

#### Remediation

##### Configuring secure cookie persistence using the Configuration utility

1. Log in to the Configuration utility.
2. Go to `Local Traffic > Profiles > Persistence`.
3. Create a new secure persistence profile with persistence type equals to `Cookie`.
4. Check the custom box for `Cookie Name` and enter a cookie name that does not conflict with any existing cookie names.
5. Check the custom box for `Cookie Encryption Use Policy` and choose the `required` option. Enter a passphrase in the `Encryption Passphrase` field.
6. Click `Finished`.
7. Assign the created persistence profile to the virtual server.

##### Configuring secure cookie persistence using TMSH

 ```
create ltm persistense cookie <profile_name>
modify ltm persistense cookie <profile_name> cookie-name <secure_cookie_name>
modify ltm persistense cookie <profile_name> cookie-encryption required
modify ltm persistense cookie <profile_name> cookie-encryption-passphrase <secure_passphrase>
modify ltm virtual <virtual_server> persist replace-all-with { <profile_name> }
save /sys config
 ```

### HTTP Server Header Information Leakage

#### Description

An attacker can get information that a web application is protected by BIG-IP system via HTTP `Server` header.  
BIG-IP system uses different HTTP Profiles for managing HTTP traffic. In particular, BIG-IP system uses HTTP Profile that specifies the string used as the `Server` name in traffic generated by BIG-IP LTM.
The default value is equal to `BigIP` or `BIG-IP` and depends on BIG-IP system version.
An attacker can detect that BIG-IP system is used in network and then know a role, type, and version of the BIG-IP system.

#### Testing

1. Run intercepting proxy or traffic intercepting browser plug-in, trap all responses from a web application.
2. If possible, log in to web application and inspect HTTP responses.
3. Send requests using HTTP and HTTPS.  
4. If HTTP Server header contains `BIG-IP` or `BigIP` value then BIG-IP is used.

The following example shows a GET request to BIG-IP and a response containing Server header inserted by BIG-IP LTM.
 ```
 GET / HTTP/1.1
 Host: example.com
 ```
 ```
 HTTP/1.0 302 Found
 Server: BigIP
 Connection: Close
 Content-Length: 0
 Location: /my.policy
 Set-Cookie: LastMRH_Session=05da1fc5;path=/;secure
 Set-Cookie: MRHSession=03e47713f1a8ef1aaa71cd9d05da1fc5;path=/;secure
 Set-Cookie: MRHSHint=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/
 ```
#### Tools
* [Metasploit Framework module] (http://www.rapid7.com/db/modules/auxiliary/scanner/http/f5_bigip_virtual_server)

#### Remediation

It is recommended to remove `Server` header from HTTP responses.

##### Removing Server header using the Configuration Utility

1. Log in to the Configuration utility.
2. Go to `Local Traffic > Profiles > Services > HTTP`.
3. Create new secure HTTP profile.
4. Enter empty string in `Server Agent Name` field.
5. Click `Finished`.
6. Assign created HTTP profile to the virtual server.

##### Removing Server header using TMSH
 ```
create ltm profile http <profile_name>
modify ltm profile http <profile_name> server-agent-name none
save /sys config
 ```

### Access to Management Interface from Internet

#### Description
If an attacker can access to BIG-IP management interface from Internet  this can lead to different attacks on BIG-IP administrative tools, unauthorized access or mass enumeration of BIG-IP systems using search engines. 
The BIG-IP system uses the following [two network connection entry points] (https://support.f5.com/kb/en-us/solutions/public/7000/300/sol7312.html):
* TMM switch interfaces
* Management interface (MGMT)

Either the TMM switch interfaces or the MGMT interface can provide administrative access to the BIG-IP system.
The TMM switch interfaces are the interfaces that the BIG-IP system uses to send and receive load-balanced traffic.
The MGMT interface is the interface to perform system management functions via browser-based or command line configuration tools.
The MGMT interface is intended for administrative traffic and can not be used for load-balanced traffic.
It is recommended to connect MGMT interface to a secure, management-only network, such as one that uses an [RFC 1918](https://tools.ietf.org/html/rfc1918) private IP address space.
Otherwise an attacker can identify BIG-IP systems in your network and then [attack them](https://www.blackhat.com/html/webcast/07182013-hacking-appliances-ironic-exploits-in-security-products.html) via management plane.

#### Testing

1. Try to use the following "googledorks":
  * inurl:"tmui/login.jsp"
  * intitle:"BIG-IP" inurl:"tmui"
2. Try to use the following queries for [Shodan](https://www.shodanhq.com/)
  * F5-Login-Page
  * WWW-Authenticate: Basic realm=BIG-IP
  * BigIP
  * BIG-IP
3. Run [Metasploit Framework module](http://www.rapid7.com/db/modules/auxiliary/scanner/http/f5_mgmt_scanner)

#### Tools
* [Metasploit Framework module](http://www.rapid7.com/db/modules/auxiliary/scanner/http/f5_mgmt_scanner)

#### Remediation

Connect MGMT interface to special management network only. Management network should operates under private ([RFC 1918](https://tools.ietf.org/html/rfc1918)) IP-address space that is completely separate from the production network.
The most secure configuration is to set "Allow None" on all Self IPs and only administer a BIG-IP using the Management Port.
Setting "Allow None" on each Self IP will block all access to BIG-IP's administrative IP addresses except for the Management Port. Access to individual ports can be selectively enabled, but this is not recommended in a highly secure environment.

To deny all connections on the self IP addresses using the Configuration utility

1. Log in to the Configuration utility.
2. Go to `Network > Self IPs`.
3. For all self IPs set `Port Lockdown` option to `Allow None`.
4. Click `Update`.

If you need to administer BIG-IP using Self IPs you should also use private [RFC 1918](https://tools.ietf.org/html/rfc1918) IP-address space.
The most unsecure configuation is to use routable IP-addresses on your Self-IPs. In this case it is highly recommended to lock down access to the networks that need it. To lock-down SSH and the GUI for a Self IP from a specific network.
For examle, to permit access from network 192.268.2.0/24 it is necessary to perform the following commands in TMSH:
 ```
modify /sys sshd allow replace-all-with { 192.168.2.* }
modify /sys httpd allow replace-all-with { 192.168.2.* }
save /sys config
 ```

### HTTP Host Header Insufficient Validation

#### Description

Host header in HTTP requests is not always validated by BIG-IP systems by default.
This validation depends on enabled modules, features and their configuration: for example, BIG-IP system in APM portal access mode performs a base sanitization of HTTP host header against XSS attacks.
In most cases BIG-IP systems process HTTP requests with arbitrary `Host` header.
This weakness can lead to vulnerabilities which can be used in [different attacks based on HTTP Host header](http://www.acunetix.com/blog/articles/automated-detection-of-host-header-attacks). For example, [DNS Rebinding](http://www.ptsecurity.com/download/DNS-rebinding.pdf), [XSS](https://www.mehmetince.net/concrete5-reflected-xss-vulnerability-via-http-header-host-parameter), [password reset poisoning](http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.htm), etc.  

#### Testing

1. Run intercepting proxy, trap all responses from a web application.
2. If possible, log in to web application. 
3. Change `Host` header in HTTP requests. If responses for requests with normal and modified Host header are the same then BIG-IP does not validate `Host` header.
 
#### Remediation

BIG-IP systems can be protected against HTTP host header attacks using Centralized Policy Matching (CPM) feature of LTM module or iRules. Let's consider an example of configuration BIG-IP system with LTM and APM modules using CPM that illustrates the main idea of this protection.
The following settings ensures that user will be redirected to `/vdesk/hangup.php3` script deleting a user's session if HTTP `Host` header contains a value different from permitted and correct hostnames.

##### Configuring host validation in CPM using the Configuration utility

1. Log in to the Configuration utility.
2. Navigate `Local Traffic > Policies`.
3. Click `Create`. Input `_host_header_validation` in the `Name` field. Add `http` to Requires box.
4. Click `Add` in Rules section.
5. Add the following Condition:
  * Operand: `http-host`
  * Event: `request`
  * Selector: `host`
  * Negotiate: `not`
  * Condition: `equals`
  * Values: `<dns_name_1>`, `<dns_name_2>`, `<dns_name_3>`, etc
6. Click `Add`.
7. Add the following Rule:
  * Target: `http-uri`
  * Event: `request`
  * Action: `replace`
  * Parameters
    * Name: `path`
    * Value: `/vdesk/hangup.php3`
8. Go to `Local Traffic > Virtual Servers`. Choose a virtual server that should be protected by CPM and click `Resources`.  9. Click `Manage` in `Policies` section and add `_http_host_validation` to `Enabled` box.
10. Click `Finished`.

##### Configuring host validation in CPM using TMSH
1. Prepare the following CPM config for host validation

 ```
ltm policy _http_host_validation {
    requires { http }
    rules {
        host_validation {
            actions {
                0 {
                    http-uri
                    replace
                    path /vdesk/hangup.php3
                }
            }
            conditions {
                0 {
                    http-host
                    host
                    not
                    values { <dns_name_1> <dns_name_2> <dns_name_3> }
                }
            }
            ordinal 1
        }
    }
    strategy first-match
}
 ```
 
2. Log in to TMSH.
3. Run the following command:

 ```
load sys config from terminal merge
 ```
 
4. Copy the config and press `CTL-D` to submit.
5. Run the following command:
 
 ```
modify ltm virtual <virtual_server> policies add { _http_host_validation }
 ```

### Mass Enumeration using Search Engines

#### Description
Web-based components of BIG-IP systems, such as APM, use different HTML pages with default values that can be used for mass enumeration.

#### Testing
Try to use the following search queries with BIG-IP keyword in [Google] (https://www.google.com/):
* intitle:"BIG-IP logout page"
* "Thank you for using BIG-IP."

#### Remediation
BIG-IP systems can be protected against web enumeration using Customization mechanism.

1. Log in to the Configuration utility.
2. Go to `Access Policy > Customization > General`.
3. Change all `BIG-IP` substrings to some neutral strings.
3. Go to `Access Policy > Customization > Advanced`.
4. Change strings with `BIG-IP` values.

For example, navigate to the `Customization Settings > Access profiles > /Common/<profile_name> > Logout > logout.inc`.
Change `<title>BIG-IP logout page</title>` to `<title>Logout page</title>`.

### APM Session Exhaustion DoS Attack

#### Description

An unauthenticated attacker can establish multiple connections with BIG-IP APM and exhaust all available sessions defined in customer's license.
In the first step of BIG-IP APM protocol the client sends a HTTP request to virtual server with access profile (/).
The BIG-IP APM creates a new session, marks it as progress (pending), decreases the number of the available sessions by one, and then redirects client to access policy URI (/my.policy).
Since BIG-IP APM allocates a new session after the first unauthenticated request and deletes the session only if an access policy timeout will be expired the attacker can exhaust all available sessions repeatedly sending initial HTTP request.
New versions of BigIP system has secure configuration by default and they are not vulnerable to this attack.

#### Testing

1. Log in to the Configuration utility.
2. Go to `Access Policy > Access Profiles > <profile_name>`.
3. Review `Max In Progress Sessions Per Client IP` setting.
4. If `Max In Progress Sessions Per Client IP` value is equal to 0 then the BigIP system is vulnerable to this attack.

#### Tools
* [Metasploit Framework module](http://www.rapid7.com/db/modules/auxiliary/dos/http/f5_bigip_apm_max_sessions)

#### Remediation

The default recommendation is to set value of `Max In Progress Sessions Per Client IP` in all access profiles to 128.

##### Protection settings using the Configuration utility

1. Log in to the Configuration utility.
2. Navigate `Access Policy > Access Profiles > <profile_name>`.
3. Set `Max In Progress Sessions Per Client IP` value to 128.
4. Click `Update` and then click `Apply Access Policy`.

##### Protection settings in the TMSH
 ```
modify apm profile access <profile_name> max-in-progress-sessions 128
modify /apm profile access <profile_name> generation-action increment
save /sys config
 ```
 
### APM Brute Force Passwords Attack
 
#### Description
By default, BIG-IP APM with any type of AAA is vulnerable to brute-force password attack.

#### Remediation
The `Minimum Authentication Failure Delay` and `Maximum Authentication Failure Delay` options or CAPTCHA can be enabled to slow down or mitigate brute-force passwords attacks against BIG-IP APM.

To enable `Minimum Authentication Failure Delay` and `Maximum Authentication Failure Delay` options using the Configuration utility

1. Log in to the Configuration utility.
2. Go to `Access Policy > Access Profiles`. Click a profile name.
3. Enable `Minimum Authentication Failure Delay` and `Maximum Authentication Failure Delay` options and change their values if necessary.
4. Click `Update` and then click `Apply Access Policy`.

To enable CAPTCHA using the Configuration utility

1. Log in to the Configuration utility.
2. Go to `Access Policy > CAPTCHA Configurations` and create a new one.
3. Go to `Access Policy > Access Profiles`. Click `Edit` link for the profile name.
4. Click `Logon Page`. Set the created CAPTCHA configuration.
5. Click `Apply Access Policy`.

## Getting an A-grade on Qualys SSL Labs

It is necessary to configure the following settings in BIG-IP's client SSL profile
* TLS_FALLBACK_SCSV extension
* HTTP Strict Transport Security
* PFS ciphers

### Enabling TLS Fallback SCSV extension
All modern and updated BIG-IP systems support this extension by default.

### Enabling Strict Transport Security
There are several ways for implementing HSTS on BigIP: HTTP profile and iRules.

#### Enabling HSTS using SSL Profile

1. Log in to the Configuration utility.
2. Go to `Local Traffic > Profiles > Services > HTTP`.
3. Choose existent or create a new HTTP profile.
4. Select `Mode` and `Include Subdomains` in the `HTTP Strict Transport Security` section.
5. Click `Update`.

#### Enabling HSTS using iRules

1. Log in to the Configuration utility.
2. Go to `Local Traffic > iRules`.
3. Create a new iRule:

 ```
### iRule for HSTS HTTPS Virtuals ###

when HTTP_RESPONSE {
  HTTP::header insert Strict-Transport-Security "max-age=31536000; includeSubDomains"
}
 ```
4. Assign the iRule to the HTTPS virtual server.

### Prioritizing PFS ciphersuites

There are many different cipher strings that prioritize PFS ciphers and can provide forward secrecy. One of them is the following:

```
ECDHE+AES-GCM:ECDHE+AES:DEFAULT:!DHE:!RC4:!MD5:!EXPORT:!LOW:!SSLv2
```

#### Configuring ciphers using SSL profile

1. Log in to the Configuration utility.
2. Go to `Local Traffic > Profiles > SSL > Client`.
3. Choose the existent or create a new cleint SSL profile.
4. Choose `Advanced` configuration mode. Input your cipher string in the `Cipher` option.
5. Click `Update`.

### Disabling SSLv3 on Management Interface

By default, SSLv3 protocol is enabled on BIG-IP management interface.

#### Disabling SSLv3 using TMSH
```
tmsh modify /sys httpd ssl-protocol "all -SSLv2 -SSLv3"
```

## Securing Administrative Access

It is necessary to configure the following settings to secure administrative access to BIG-IP
* SSH
* Legal notification banner
* Inactive administrative session timeout
* Password policy for administrative user

### SSH
SSH is a protocol that provides secure remote access, remote command execution, and file transfer. It is possible to enable or SSH  accesss to management interface and restrict SSH access to trusted hosts or subnets.

#### Configuring SSH access

1. Log in to the Configuration utility.
2. Go to `System > Platform`.
3. For the setting labeled `SSH Access`, verify that the box is checked/unchecked according with your security policy.
4. Restrict SSH access using the field labeled `SSH IP Allow` and adding an IP address or address range that must have SSH access to the system only.

### Legal Notification Banner

It is recommended that a legal notification banner is presented on all interactive sessions to ensure that users are notified of the security policy being enforced and to which they are subject.

#### Configuring legal notification banner

1. Log in to the Configuration utility.
2. Go to `System > Preferences`.
3. For the setting labeled `Show The Security Banner On The Login Screen`, verify that the box is checked. This ensures that security message you specify displays on the login screen of the BIG-IP Configuration utility.
4. Add a banner according with your security policy. Example of the [banner](http://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Security/Baseline_Security/securebasebook/appendxA.html):

  ```
UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED
 You must have explicit, authorized permission to access or configure this device.
 Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties.
 All activities performed on this device are logged and monitored.
  ```
  
5. Click `Update`

### Inactive Administrative Session Timeout

It is recommended that all sessions should be restricted using an idle or inactivity timeout. This timeout defines the amount of time a session will remain active in case there is no activity in the session, closing and invalidating the session upon the defined idle period since the last HTTP request received by the web application for a given session.

#### Configuring inactive administrative session timeout

1. Log in to the Configuration utility.
2. Go to `System > Preferences`.
3. In the field labeled `Idle Time Before Automatic Logout`, revise the default value. It is recommended to use a value of 120 seconds.
4. For the setting labeled `Enforce Idle Timeout While Viewing The Dashboard`, verify that the box is checked.  In this case session timeout is enforced while dashboard is running.
5. Click `Update`.

### Connection Settings

It is recommended that all connections to GUI should be restricted by number and IP-address.

#### Configuring connection settings

1. Log in to the Configuration utility.
2. Go to `System > Preferences`.
3. For the setting labeled `Require A Consistent Inbound IP For the Entire Web Session `, verify that the box is checked.
4. In the `System Settings` choose `Advanced`.
5. In the field labeled `Maximum HTTP Connections To Configuration Utility `, revise the default value. It is recommended to use a value of 10 seconds.
6. Click `Update`.

### Password Policy for Administrative Users

It is recommended to require BIG-IP system users to create strong passwords and to specify the maximum number of BIG-IP Configuration utility login failures that the system allows before the user is denied access. Password policy can not be assigned to users with `Administrator` role or to `root` user. 

#### Configuring a password policy for administrative users
1. Log in to the Configuration utility.
2. Go to `System > Users`. Click `Authentication`.
3. From the `Secure Password Enforcement` list, select `Enabled`. Additional settings appear on the screen.
4. For the `Minimum Length` and `Required Characters` settings, configure the default values, according to your organization's internal security requirements.
5. In the `Maximum Login Failures` field, specify a number. If the user fails to log in the specified number of times, the user is locked out of the system. Therefore, F5 Networks recommends that you specify a value that allows for a reasonable number of login failures before user lockout.
6. Click `Update`.

## Vulnerability Search

[Vulners.com](https://vulners.com) service can be used to search known vulnerabilities of the BIG-IP systems. 

The examples of requests:
- `affectedSoftware.name:"BigIP" or affectedSoftware.name:"BIG-IP"`
- `type:F5`

You can find additional information [here](https://vulners.com/#help).

## References
* [F5 Networks Official Site] (https://f5.com/products/big-ip)
* [BIG-IP Modules Datasheet](https://www.f5.com/pdf/products/big-ip-modules-ds.pdf)
* [David Holmes. 10 Settings to Lock Down your BIG-IP] (https://devcentral.f5.com/articles/10-settings-to-lock-down-your-big-ip)
* [SOL13092: Overview of securing access to the BIG-IP system](https://support.f5.com/kb/en-us/solutions/public/13000/000/sol13092.html)
* [SOL13309: Restricting access to the Configuration utility by source IP address](https://support.f5.com/kb/en-us/solutions/public/13000/300/sol13309.html)
* [F5 TLS & SSL Practices](http://www.slideshare.net/bamchenry/f5-tls-ssl-practices)
* [OWASP Secure Configuration Guide: BigIP] (https://www.owasp.org/index.php/SCG_D_BIGIP)
