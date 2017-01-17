function Power-Client
{
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('c')]
        [string]$RemoteComputer,

        [Parameter()]
        [Alias('p')]
        [int]$port
    )

    function send-file
    {   
        [CmdletBinding()]
        Param (
        [Parameter()]
        [string]$local,

        [Parameter()]
        [string]$remote
        )

        $FileStream = New-Object IO.FileStream @($local, [IO.FileMode]::Open)

        Write-host "`n[***]Attempting to send " $local "to" $destination -ForegroundColor Cyan
        Write-Verbose "[***] Local file exists.."
        Write-Verbose "[***] sending file.."
        
        $SslStream.Write($sendback, 0, $sendback.Length)
        $SslStream.Flush()
                
        $destination = ("\\" + $serverip.IPAddressToString + "\" + $remote)

        if ($BytesLeft = $FileStream.Length) {
                  
            $FileOffset = 0
            if ($BytesLeft -gt 4608) { # Max packet size for Ncat

                $BytesToSend = New-Object Byte[] 4608
                        
                while ($BytesLeft -gt 4608) {
                    [void]$FileStream.Seek($FileOffset, [IO.SeekOrigin]::Begin)
                    [void]$FileStream.Read($BytesToSend, 0, 4608)
                                
                    $FileOffset += 4608
                    $BytesLeft -= 4608
                    $SslStream.Write($BytesToSend, 0, $BytesToSend.Length)         
                } 

                # Send last packet
                $BytesToSend = New-Object Byte[] $BytesLeft
                [void]$FileStream.Seek($FileOffset, [IO.SeekOrigin]::Begin)
                [void]$FileStream.Read($BytesToSend, 0, $BytesLeft)

                $SslStream.Write($BytesToSend, 0, $BytesToSend.Length)
            }
            else { # Only need to send one packet
                $BytesToSend = New-Object Byte[] $BytesLeft
                [void]$FileStream.Seek($FileOffset, [IO.SeekOrigin]::Begin)
                [void]$FileStream.Read($BytesToSend, 0, $BytesLeft)

                $SslStream.Write($BytesToSend, 0, $BytesToSend.Length)
            }
            write-verbose "[***] Done sending bytes.."
            $FileStream.Flush()
            $FileStream.close()
            $FileStream.Dispose()
                
            write-host ("`nFile " + $local + " was sent successfully to " + $destination) -ForegroundColor Cyan
            
            if ($local -match ".zip"){
                write-host ("`n[***]Unzipping " + $destination + " Please Wait!") -ForegroundColor Cyan
            }
        }      
    }

    function Receive-file
    {
        [CmdletBinding()]
        Param (
        [Parameter()]
        [string]$local,

        [Parameter()]
        [string]$remote
        )
        
        if (Test-Path $local){remove-item $local -Force}
        else {write-verbose "Local file does not exist. Creating a new one..."}

        $FileStream = New-Object IO.FileStream @($local, [IO.FileMode]::Append)       
        $BytesToReceive = New-Object Byte[] 4608

        while ($true)
        {
            $Fileread = $SslStream.Read($BytesToReceive, 0, $BytesToReceive.Length)
            
            if($Fileread -eq 0){break}                  
            else{          
                [Array]$Filebytesreceived = $BytesToReceive[0..($Fileread -1)]
                [Array]::Clear($BytesToReceive, 0, $Fileread)
            }
                          
            if ($Fileread -eq 4608) {$FileStream.Write($Filebytesreceived, 0, $Filebytesreceived.Length); continue}
            else{                        
                $FileStream.Write($Filebytesreceived, 0, $Filebytesreceived.Length)
                $FileStream.Flush()
                $FileStream.Dispose()
                break
            }
            $FileStream.Flush()
            $FileStream.Dispose()
            break
        }
        Write-Verbose "[***] $remote has been retrieved succesfully"
        get-item $local                      
    }

    function invoke-space
    {
        $sendback = $EncodingType.GetBytes(' ')
        $SslStream.Write($sendback, 0, $sendback.Length)
        $SslStream.Flush() 
    }
        
    $Tcpclient = New-Object System.Net.Sockets.TcpClient
    $Tcpclient.Connect($RemoteComputer, $port)    
    $serverip = [System.Net.IPAddress]::Parse($RemoteComputer)  

    if($TCPClient.Connected){
        Write-Verbose "[***]Connection to $($serverip.IPAddressToString):$port [TCP] succeeded!"
    }
    else{
        Write-Verbose "[!!!]Connection to $($serverip.IPAddressToString):$port [TCP] Failed!" $($_.Exception.Message)
    }    

    $TcpNetworkstream = $Tcpclient.GetStream()
    $Receivebuffer = New-Object Byte[] $TcpClient.ReceiveBufferSize
    $EncodingType = New-Object System.Text.ASCIIEncoding

    $SslStream = New-object System.Net.Security.SslStream ($TcpNetworkStream, $false, { param($Sender, $Cert, $Chain, $Policy) return $true})
    
    #$SslStream.AuthenticateAsClient("Wardog",$null,[System.Security.Authentication.SslProtocols]::Tls, $null)
    $SslStream.AuthenticateAsClient("Wardog",$null,[System.Security.Authentication.SslProtocols]::Tls12, $null)

    Write-Verbose "SSLStream Encrypted: $($SslStream.IsEncrypted)"
    Write-Verbose "SSLStream Signed: $($SslStream.IsSigned)"

    try {
        while ($TCPClient.Connected){         
            $Bytesreceived = $null
            $Read = $SslStream.Read($Receivebuffer, 0,$Receivebuffer.Length)
                     
            if($Read -eq 0){break}                  
            else{
                [Array]$Bytesreceived += $Receivebuffer[0..($Read -1)]
                [Array]::Clear($Receivebuffer, 0, $Read)
            }

            if ($TcpNetworkStream.DataAvailable) {continue}
            else {
                write-host -NoNewline $EncodingType.GetString($Bytesreceived).TrimEnd("`r")
                
                $sendback = $EncodingType.GetBytes((read-host) + "`n")

                $ScriptBlock = $null
                $ScriptBlock = [scriptblock]::Create($EncodingType.GetString($sendback))

                if ($Scriptblock -match "send-file"){               
                    try {Invoke-command -ScriptBlock $Scriptblock}
                    catch {Write-Warning $_.Exception.Message; invoke-space}
                          
                }
                elseif($ScriptBlock -match "receive-file"){
                    $check = $null
                    $SslStream.Write($sendback, 0, $sendback.Length)
                    $SslStream.Flush()
                    
                    $Read = $SslStream.Read($Receivebuffer, 0, $Receivebuffer.Length)
                    if( $Read -eq 0){break}                  
                    else{            
                        [Array]$Bytesreceived = $Receivebuffer[0..($Read -1)]
                        [Array]::Clear($Receivebuffer, 0, $Read)
                    }
                    $check = $EncodingType.GetString($Bytesreceived).TrimEnd("`r")
                    if ($check -match "Exception"){
                        write-warning $check
                    }
                    else{ 
                        try {Invoke-command -ScriptBlock $Scriptblock}
                        catch {Write-Warning $_.Exception.Message}
                    }
                    invoke-space                       
                }
                else {
                    $SslStream.Write($sendback, 0, $sendback.Length)
                    $SslStream.Flush()
                }
            }  
        }
    }
    catch{ Write-Warning "`n[!!!]TCP connection is broken, exiting.."}                        

    try{
        if ($PSVersionTable.CLRVersion.Major -lt 4) { $Tcpclient.Close(); $SslStream.Close()}
        else {$SslStream.Dispose(); $Tcpclient.Dispose()}
        Write-host "`n[**] TCPClient Connected: $($Tcpclient.Connected)" -ForegroundColor Cyan
        Write-host "[**] SSLStream was closed/disposed gracefully..`n" -ForegroundColor Cyan
    }
    catch { Write-Warning "[!!!]Failed to close TCP Stream"}       
}
