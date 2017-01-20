function invoke-vt
{
<#
.SYNOPSIS
Function which allows a security analyst to query the VT database via its API 
.DESCRIPTION
Function which allows a security analyst to query the VT database via its API. One could either provide one IOC or
a text file with several IOCs one per line. You can query for Hash, IP, URL or Domain names.
.PARAMETER Path
Path of a text file or a simple indicator (Text file must have IOCs of the same type)
.PARAMETER apikey
VirusTotal API key
.PARAMETER type
Type of IOC you are providing (url,domain,file or ip)
.EXAMPLE
PS > C:\scripts> invoke-vt -path 'http://138.201.44.4/' -api yourapikey -type url
Malicious IOC
Reference : https://www.virustotal.com/url/d62381a3a639d236648aeed887157ddd8af4166d3ba1761d0ef87fae
            dd69c601/analysis/1484889308/
IOC       : http://138.201.44.4/
Scan Date : 2017-01-20 05:15:08
Hits      : 2
.EXAMPLE
PS C:\scripts> invoke-vt -path 14b9d54f07f3facf1240c5ba89aa2410 -apikey yourapikey -type file
Malicious IOC
Reference : https://www.virustotal.com/file/680fca118ba3283b4eb57d187258d2d61e6129cac9304497915ce7d
            3b1fca510/analysis/1484656730/
IOC       : 14b9d54f07f3facf1240c5ba89aa2410
Scan Date : 2017-01-17 12:38:50
Hits      : 35
.EXAMPLE
PS C:\scripts> invoke-vt -path C:\IOCs_List.txt -apikey yourapikey -type file
Malicious IOCs found in VT Database
Reference                IOC                      Scan Date                                    Hits
---------                ---                      ---------                                    ----
https://www.virustota... 212d3ca8d85b389d35825... 2017-01-20 04:38:01                             7
https://www.virustota... 14b9d54f07f3facf1240c... 2017-01-17 12:38:50                            35
https://www.virustota... 2b0bd7e43c1f98f9db804... 2017-01-20 17:30:37                             3
https://www.virustota... 63698ddbdff5be7d5a7ba... 2017-01-18 22:18:18                            39
The results have been exported to a csv file and stored in your Downloads folder
#>

    [CmdletBinding()]
    param(
    [Parameter(Mandatory = $true)]
    [string]$path,
    [Parameter(Mandatory = $true)]
    [String]$apikey,
    [Parameter()]
    [string]$type
     
    )
    
    add-type -AssemblyName system.web.extensions
    $invokeweb = New-Object system.net.webclient
    $ps_js = New-Object system.web.script.serialization.javascriptserializer
    
    if ($Path -match ".txt")
    {
        $CsvArray = @()
        $date = Get-Date -format _yyyy-MM-dd_HHmms
        $content = get-content $Path
        foreach ($line in $content)
        {
            Switch($type)
            {
                "file" { $result = $invokeweb.uploadstring("https://www.virustotal.com/vtapi/v2/file/report", "resource=$line&apikey=$apikey")}
                "ip" { $result = $invokeweb.uploadstring("https://www.virustotal.com/vtapi/v2/ip-address/report", "resource=$line&apikey=$apikey")}
                "url" { $result = $invokeweb.uploadstring("https://www.virustotal.com/vtapi/v2/url/report", "resource=$line&apikey=$apikey")}
                "domain" {$result = $invokeweb.uploadstring("https://www.virustotal.com/vtapi/v2/domain/report", "resource=$line&apikey=$apikey")}  
            }                       
            [array]$jsonresults = $ps_js.Deserializeobject($result)
            
            foreach ($item in $jsonresults)
            {               
                $OTable = new-object -TypeName PSObject -Property @{
                'IOC' = $item.resource
                'Hits' = $item.positives
                'Scan Date' = $item.scan_date
                'Reference' = $item.permalink
                }              
                if (($item.response_code -eq 1) -and ($item.positives -ne 0))
                {
                   $CsvArray += $OTable
                }
                else{ continue }
             }
        }
        if ($CsvArray.count -gt 0)
        {
            write-host "Malicious IOCs found in VT Database" -BackgroundColor Red
            $CsvArray | FT
            write-host "`nThe results have been exported to a csv file and stored in your Downloads folder" -ForegroundColor yellow
            $CsvArray | export-csv -NoTypeInformation -Encoding Unicode ($env:USERPROFILE + "\Downloads\VTResults_" + $date + ".csv")
        }          
    }   
    else
    {       
        Switch($type)
        {
            "file" { $result = $invokeweb.uploadstring("https://www.virustotal.com/vtapi/v2/file/report", "resource=$path&apikey=$apikey")}
            "ip" { $result = $invokeweb.uploadstring("https://www.virustotal.com/vtapi/v2/ip-address/report", "resource=$path&apikey=$apikey")}
            "url" { $result = $invokeweb.uploadstring("https://www.virustotal.com/vtapi/v2/url/report", "resource=$path&apikey=$apikey")}
            "domain" {$result = $invokeweb.uploadstring("https://www.virustotal.com/vtapi/v2/domain/report", "resource=$path&apikey=$apikey")}  
        }  
        [array]$jsonresults = $ps_js.Deserializeobject($result)
        
        foreach ($item in $jsonresults)
        {               
            $OTable = new-object -TypeName PSObject -Property @{
            'IOC' = $item.resource
            'Hits' = $item.positives
            'Scan Date' = $item.scan_date
            'Reference' = $item.permalink
            }      
        
            if ($item.response_code -eq 0)
            {
                write-host "`nNot found in VT database." -ForegroundColor cyan
            }
            elseif (($item.response_code -eq 1) -and ($item.positives -ne 0))
            {
                Write-host "`nMalicious IOC" -BackgroundColor Red
                $OTable | Format-list
            }
            elseif (($item.response_code -eq 1))
            {
                Write-host "`nReported clean" -ForegroundColor Yellow               
            }           
        }   
    }
}
