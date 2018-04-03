SYNOPSIS

	Dictionary based SMB attack

DESCRIPTION

    This script takes either a list of users or, if not specified, will query the domain 
	for a list of users on every brute attempt. The users queried will have a badPwdCount 
	attribute of two less than the LockoutThreshold to ensure they are not locked in the brute
	attempt, with a new list being queried for every attempt. Designed to simply input the 
	LockoutThreshold as well as a password list and then run.
	
	You can find password dictionary from  
		https://wiki.skullsecurity.org/Passwords
	or
		https://github.com/duyetdev/bruteforce-database
		
	I developed this code using this https://www.shellntel.com/blog/2016/7/7/smart-smb-brute-forcing
		
EXAMPLE

	PS C:\> Import-Module DictionaryBasedSMBAttack.ps1 (*if you have not done it before)
    PS C:\> DictionaryBasedSMBAttack -DomainName example.com -PasswordList InputPasswordList.txt -LockoutThreshold 4

	[*] Performing prereq checks.
	[*] PDC: DC1.example.com
	[*] Initiating brute. Unless -ShowVerbose was specified, only successes will show...
	[+] Success! Username: TestUser. Password: 123456
	[*] Completed.

PARAMETER DomainName

	A domain name to attack.
	
PARAMETER UserList

	A text file of userids (one per line) to brute. Do not append DOMAIN\ in front of the userid.
	If this parameter is not specified, the script will retrieve a new list of user accounts for
	each attempt to ensure accounts are not locked.
	
PARAMETER PasswordList

    A text file of password (one per line) to Dictionary based attack.
	
PARAMETER LockoutThreshold

	The domain setting that specifies the number of bad login attempts before the account locks.
	To discover this, open a command prompt from a domain joined machine and run "net accounts".
	
PARAMETER Delay

	The delay time (in milliseconds) between each brute attempt. Default 100.
	
PARAMETER ShowVerbose

	Will display Failed as well as Skipped attempts. Generates a ton of data.
	
PARAMETER StopOnSuccess

	The script will return after the first successful authentication.
