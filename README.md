## Repair Bad Tweaks

### Why?
As tweaking windows becomes more popular self proclaimed experts incorrectly interpret microsoft documentation and other sources. This causes less tech savvy people to blindly trust these "tweakers" and negatively effect the performance of their operating system. This script aims to revert these tweaks to their default values. 

### How to Use?
#### Option 1: 
Run Script From Terminal or PowerShell Prompt as Admin
````
 iwr 'https://raw.githubusercontent.com/zoicware/RepairBadTweaks/main/RepairTweaks.ps1' | iex 
 ````

 #### Option 2:
 Download Script and Run Locally 

 **Note:** Unblock PowerShell Scripts on Windows 11 before running to avoid it closing instantly

 ```Set-executionpolicy Unrestricted -Force```