# Classes d'outils Parrot (assignables par agent)

Source: https://tools.parrotsec.org/tools.json — 445 outils, 14 classes.

Chaque classe peut etre confiee a un agent : il implemente un `Expert`
(prompt dedie + outils + routage + analyse) pour cette classe.

## Information Gathering  — 82 outils  (`01-info-gathering`)

- **Information Gathering (direct)** (23) : `amap`, `arp-scan`, `autorecon`, `clamav`, `dmitry`, `geoip-bin`, `ike-scan`, `kerberoast`, `legion`, `mac-robber`, `maltego`, `naabu`, `ndiff`, `netdiscover`, `nmap`, `nmapsi4`, `p0f`, `patchleaks`, `recon-ng`, `savi`, `syft`, `trufflehog`, `witnessme`
- **DNS Analysis** (9) : `amass`, `certgraph`, `dnsenum`, `dnsmap`, `dnsrecon`, `dnstracer`, `dnswalk`, `fierce`, `urlcrazy`
- **SMTP Analysis** (3) : `ismtp`, `smtp-user-enum`, `swaks`
- **OSINT Analysis** (14) : `assetfinder`, `bing-ip2hosts`, `cloud-enum`, `emailharvester`, `goofile`, `inspy`, `instaloader`, `metagoofil`, `osrframework`, `python3-censys`, `python3-shodan`, `sherlock`, `spiderfoot`, `theharvester`
- **SMB Analysis** (5) : `enum4linux`, `enum4linux-ng`, `nbtscan`, `polenum`, `smbmap`
- **Route Analysis** (4) : `0trace`, `intrace`, `irpas`, `netmask`
- **Live Host Identification** (6) : `arping`, `fping`, `hping3`, `iputils-arping`, `maryam`, `ncat`
- **SSL Analysis** (5) : `ssldump`, `sslh`, `sslscan`, `sslyze`, `tlssled`
- **IDS/IPS Identification** (5) : `firewalk`, `fragrouter`, `ftester`, `lbd`, `wafw00f`
- **SNMP Analysis** (3) : `braa`, `onesixtyone`, `snmpcheck`
- **Network & Port Scanners** (5) : `2ping`, `dbd`, `masscan`, `netcat-openbsd`, `unicornscan`

## Vulnerability Analysis  — 42 outils  (`02-vulnerability-analysis`)

- **Vulnerability Analysis (direct)** (9) : `afl++`, `defectdojo`, `hb-honeypot`, `peass`, `python3-bandit`, `sentrypeer`, `testssl.sh`, `tnscmd10g`, `unix-privesc-check`
- **Cisco Tools** (6) : `cisco-auditing-tool`, `cisco-ocs`, `cisco-torch`, `copy-router-config`, `nipper-ng`, `yersinia`
- **Stress Testing** (6) : `dhcpig`, `siege`, `slowhttptest`, `t50`, `thc-ipv6`, `thc-ssl-dos`
- **Fuzzing Tools** (5) : `bed`, `doona`, `sfuzz`, `siparmyknife`, `spike`
- **VoIP Tools** (16) : `enumiax`, `iaxflood`, `inviteflood`, `ohrwurm`, `protos-sip`, `rtpbreak`, `rtpflood`, `rtpinsertsound`, `rtpmixsound`, `sctpscan`, `sipp`, `sipsak`, `sipvicious`, `twinkle`, `twinkle-console`, `voiphopper`

## Web Application Analysis  — 38 outils  (`03-webapp-analysis`)

- **Web Application Analysis (direct)** (9) : `httrack`, `paros`, `parsero`, `s3scanner`, `skipfish`, `webscarab`, `wig`, `wpscan`, `zaproxy`
- **CMS & Framework Identification** (1) : `joomscan`
- **Web Crawlers & Directory Bruteforce** (12) : `apache-users`, `arjun`, `cutycapt`, `dirb`, `dirbuster`, `dirsearch`, `feroxbuster`, `ffuf`, `gobuster`, `gospider`, `uniscan`, `wfuzz`
- **Web Application Proxies** (3) : `burpsuite`, `caido`, `goshs`
- **Web Vulnerability Scanners** (13) : `cadaver`, `davtest`, `heartleech`, `jboss-autopwn`, `jsql-injection`, `nikto`, `owasp-mantra-ff`, `padbuster`, `wapiti`, `watobo`, `websploit`, `whatweb`, `xsser`

## Exploitation Tools  — 24 outils  (`04-exploitation-tools`)

- **Exploitation Tools (direct)** (7) : `hashrat`, `msfpc`, `netexec`, `pacu`, `pocsuite3`, `routersploit`, `termineter`
- **Metasploit Framework** (1) : `armitage`
- **Social Engineering** (2) : `beef-xss`, `set`
- **Exploit Search** (2) : `exploitdb-tiny`, `pompem`
- **Payload Generators** (3) : `phpggc`, `shellnoob`, `unicorn-magic`
- **Web Applications** (5) : `commix`, `sqldict`, `sqlmap`, `sqlninja`, `sqlsus`
- **Database Exploit** (4) : `mdbtools`, `odat`, `oscanner`, `sidguesser`

## Password Attacks  — 45 outils  (`05-password-attacks`)

- **Password Attacks (direct)** (2) : `hash-identifier`, `hashid`
- **Online Attacks** (13) : `brutespray`, `changeme`, `crowbar`, `device-pharmer`, `gpp-decrypt`, `hydra`, `hydra-gtk`, `maskprocessor`, `medusa`, `ncrack`, `patator`, `statsprocessor`, `thc-pptp-bruter`
- **Offline Attacks** (14) : `bruteforce-salted-openssl`, `crackle`, `fcrackzip`, `hashcat`, `john`, `johnny`, `multiforcer`, `pdfcrack`, `rainbowcrack`, `rarcrack`, `rcracki-mt`, `sipcrack`, `sucrack`, `truecrack`
- **Local Attacks** (8) : `bruteforce-luks`, `chntpw`, `cmospwd`, `creddump7`, `ophcrack`, `ophcrack-cli`, `passing-the-hash`, `samdump2`
- **Password Profiling & Wordlists** (8) : `cewl`, `crunch`, `pipal`, `rsmangler`, `seclists`, `twofi`, `username-anarchy`, `wordlists`

## Maintaining Access  — 34 outils  (`10-maintaining-access`)

- **Maintaining Access (direct)** (6) : `bloodhound`, `dnscat2-client`, `dnscat2-server`, `starkiller`, `villain`, `windows-binaries`
- **OS Backdoors** (6) : `convoc2`, `cryptcat`, `powershell-empire`, `pwncat`, `sbd`, `sliver`
- **Web Backdoors** (6) : `htshells`, `laudanum`, `nishang`, `webacoo`, `webshells`, `weevely`
- **Tunneling & Exfiltration** (12) : `dns2tcp`, `godoh`, `iodine`, `miredo`, `proxychains`, `proxychains4`, `proxytunnel`, `ptunnel`, `pwnat`, `socat`, `stunnel4`, `udptunnel`
- **AV Evasion** (4) : `exe2hexbat`, `hyperion`, `shellter`, `veil-evasion`

## Post Exploitation  — 16 outils  (`08-post-exploit`)

- **Post Exploitation (direct)** (12) : `chisel`, `cymothoa`, `evil-winrm`, `evil-winrm-py`, `ibombshell`, `koadic`, `lynis`, `mimikatz`, `ncat-w32`, `powercat`, `powersploit`, `xspy`
- **Privilege Escalation** (1) : `linux-exploit-suggester`
- **Hash & Password Dump** (2) : `dumpzilla`, `wce`
- **Passing the Hash Attack** (1) : `freerdp3-x11`

## Wireless Testing  — 38 outils  (`06-wireless-attacks`)

- **Wireless Testing (direct)** (7) : `fern-wifi-cracker`, `kismet-core`, `mdk3`, `pixiewps`, `reaver`, `wifite`, `wig-ng`
- **802.11 Wireless Tools** (10) : `aircrack-ng`, `airgeddon`, `asleap`, `bully`, `cowpatty`, `eapmd5pass`, `freeradius`, `freeradius-wpe`, `sparrow-wifi`, `wifi-honey`
- **Bluetooth Tools** (7) : `bluelog`, `blueranger`, `bluesnarfer`, `bluez-hcidump`, `btscanner`, `redfang`, `spooftooph`
- **Software Defined Radio** (6) : `gqrx-sdr`, `gr-air-modes`, `inspectrum`, `rfcat`, `rtl-sdr`, `rtlsdr-scanner`
- **RFID & NFC Tools** (5) : `libfreefare-bin`, `libnfc-bin`, `mfcuk`, `mfoc`, `mfterm`
- **Other Wireless Tools** (3) : `gnuradio`, `hackrf`, `ubertooth`

## Reverse Engineering  — 20 outils  (`07-reverseengineer`)

- **Reverse Engineering (direct)** (7) : `androguard`, `android-sdk`, `apktool`, `detect-it-easy`, `dex2jar`, `ghidra`, `rizin-cutter`
- **Disassemblers** (2) : `bddisasm`, `libsmali-java`
- **Debuggers** (5) : `edb-debugger`, `gdb`, `gdb-gef`, `javasnoop`, `ollydbg`
- **Decompilers** (4) : `bytecode-viewer`, `jadx`, `jd-gui`, `recstudio`
- **Radare2 Framework** (1) : `radare2`
- **Rizin Framework** (1) : `rizin`

## Sniffing & Spoofing  — 29 outils  (`09-sniffing-spoofing`)

- **Sniffing & Spoofing (direct)** (13) : `bettercap`, `etherape`, `etherwake`, `ettercap-graphical`, `ettercap-text-only`, `ferret-sidejack`, `hamster-sidejack`, `macchanger`, `mitmproxy`, `python3-impacket`, `python3-scapy`, `responder`, `wireshark`
- **Network Sniffers** (7) : `chaosreader`, `darkstat`, `driftnet`, `hexinject`, `netsniff-ng`, `sslsniff`, `tcpflow`
- **Spoofing and MITM** (9) : `dnschef`, `dsniff`, `evil-ssdp`, `fiked`, `isr-evilgrade`, `rebind`, `sniffjoke`, `sslsplit`, `tcpreplay`

## Digital Forensics  — 46 outils  (`11-forensics`)

- **Digital Forensics (direct)** (23) : `autopsy`, `binwalk`, `bulk-extractor`, `chkrootkit`, `extundelete`, `foremost`, `galleta`, `hashdeep`, `inetsim`, `mc`, `missidentify`, `procdump`, `pst-utils`, `reglookup`, `regripper`, `rkhunter`, `ssdeep`, `undbx`, `unhide`, `vinetto`, `volatility3`, `xplico`, `yara`
- **PDF Forensics Tools** (2) : `pdf-parser`, `pdfid`
- **Sleuth Kit Suite** (2) : `grokevt`, `sleuthkit`
- **Forensic Carving Tools** (13) : `ext3grep`, `ext4magic`, `magicrescue`, `myrescue`, `pasco`, `pev`, `recoverdm`, `recoverjpeg`, `rifiuti`, `rifiuti2`, `safecopy`, `scalpel`, `scrounge-ntfs`
- **Forensic Imaging Tools** (6) : `afflib-tools`, `dc3dd`, `dcfldd`, `ddrescue`, `ewf-tools`, `guymager`

## Reporting Tools  — 4 outils  (`12-reporting`)

- **Reporting Tools (direct)** (4) : `dradis`, `eyewitness`, `faraday`, `neo4j`

## Automotive  — 1 outils  (`13-automotive`)

- **Can Utils** (1) : `can-utils`

## AI Tools  — 5 outils  (`14-ai-tools`)

- **AI Tools (direct)** (5) : `hexstrike-ai`, `mcpwn`, `opencode`, `pi-dev`, `unsloth`

## Autres (System Services / Utility / ...)  — 21 outils  (`misc`)

- **Database** (2) : `mariadb-server`, `postgresql`
- **Development** (2) : `arduino`, `powershell`
- **Engineering** (1) : `chirp`
- **HTTP** (2) : `apache2`, `nginx`
- **Metasploit** (1) : `metasploit-framework`
- **Network** (3) : `firefox`, `firefox-esr`, `nyx`
- **OpenVas - Greenbone** (1) : `gvm`
- **SSH** (1) : `openssh-server`
- **Utility** (8) : `coreutils`, `gpa`, `keepassxc`, `mat2`, `sirikali`, `woeusb-ng`, `zulucrypt-gui`, `zulumount-gui`

