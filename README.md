## Repair Bad Tweaks

<img width="239" alt="image" src="https://github.com/user-attachments/assets/5226dccc-6d13-4892-bbfc-1a9f87bf269b">


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

### Tweaks Explained
- **Jump to a Tweak:**

    - [Svc Split Threshold](#svc-split-threshold)
    
    - [Bcdedit](#bcdedit)
    - [Timer Resolution](#timer-resolution)
    - [Win32PrioritySeparation](#win32priorityseparation)
    - [Tcp Auto-Tuning](#tcp-auto-tuning)
    - [Prefetch and Superfetch (Sysmain)](#prefetch-and-superfetch-sysmain)
    - [Windows Error Reporting](#windows-error-reporting)
    - [Ordinary DPCs](#ordinary-dpcs)
    - [Spectre Meltdown Mitigations](#spectre-meltdown-mitigations)
    - [HPET](#hpet)
    - [Mouse Keyboard Queue Size](#mouse-keyboard-queue-size)
    - [Csrss Priority](#Csrss-Priority)


### Svc Split Threshold
- This tweak is completely visual in task manager and does not actually decrease processes. Microsoft recommends having a separate service host for certain services to increase system stability and resource management [Read More](https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring)


### Bcdedit
 - Values Checked and Repaired: 
    - useplatformclock
    - disabledynamictick
    - useplatformtick
    - tscsyncpolicy

These values are not set by default and should only be used for debugging (recommended by microsoft). These are typically changed in relation to timer res (read more below).
### Timer Resolution
 - Possibly the most widely misunderstood part of windows as this tweak is "believed" by many to decrease input lag and increase fps. Unfortunately timer resolution has nothing to do with either of these things. Operating system timers are used to sync events and keep track of how long a process took to complete. This is essential in online gaming where things are not in real time rather predicted. Many apps will set timer resolution to 1ms, however this is simply a resolution not a set value. Some people have noticed that this value is not always exactly the same, this is by design [Read More](https://stackoverflow.com/questions/3744032/why-are-net-timers-limited-to-15-ms-resolution)


 **NOTE** Windows does not use just 1 timer to keep track of events there are many timers you can see them with cpuz, this is also why professional benchmarks are measured using a number of these to get the most accurate metrics. Additionally, for very fast/accurate events a performance counter is likely to be used [Read More](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter)


### Win32PrioritySeparation
 - This registry value tells the windows scheduler how much cpu time a process should get. While there is lots of options outside of the two "**Adjust for best performance: programs or background services**" in legacy control panel, the default value when using "Programs" gives the scheduler the ideal cpu time for boosting foreground apps (longer cpu time).
 **NOTE This will not affect input lag in anyway as I/O are received as interrupts and take cpu priority**

### Tcp Auto-Tuning
 - Auto tuning allows the system to dynamically adjust the receive window for incoming data using TCP [Transmission Control Protocol] [Read More](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/receive-window-auto-tuning-for-http#how-receive-window-auto-tuning-feature-improves-data-transfer). For online gaming we do not care about this protocol as the more important events are being sent using UDP [User Datagram Protocol]. This also means the popular tcp optimizer program is completely useless for improving your network related to gaming.


### Prefetch and Superfetch (Sysmain)
 - Prefetch in Windows caches necessary data for apps instead of retrieving it from memory every time the program is launched. This helps apps to start up faster with no negative system performance drawbacks (some disk space...).


 - Superfetch is very similar to prefetch however it is able to change its caching parameters based on your frequently used apps. This is important because why would you need to cache an app you only used once. Disabling either of these will only slow your operating system down and increase loading times of apps.

### Windows Error Reporting
 - For some reason some tweak guides will disable windows error reporting. If this service is disabled no mini dump file will be made when getting a BSOD. So good luck reading about the error code with your preferred bluescreen viewer. 

### Ordinary DPCs
 - DPC [Deferred Procedure Call] tells the windows scheduler to defer a lower priority task for an interrupt (typically I/O). Starting in Vista Microsoft added threaded dpcs to decrease system latency when lots of dpcs are on the system. For some reason people think using ordinary dpcs helps input lag while Microsoft explicitly recommend using threaded [Read More](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-threaded-dpcs)

### Spectre Meltdown Mitigations
- Disabling these mitigations does not improve gaming performance and only leaves your system vulnerable to very dangerous exploits. You can find many benchmarks online showing that disabling these does not help however I always recommend doing your own with a fps analytics tool such as CapFrameX.

### HPET
 - Luckily this tweak is quite "legacy" however some people still disable HPET in device manager. This is a hardware timer similar to performance counter and is able to get extremely precise events. This was likely thought to help latency in the past because of the decrease latency reading in latencymon. HPET can produce interrupts thus when disabling latencymon will show a lower reading [Read More](https://en.wikipedia.org/wiki/High_Precision_Event_Timer).

### Mouse Keyboard Queue Size
 - These registry values decide how many bytes are allocated to the non-paged pool for mice and keyboards by default mice get 24 bytes and keyboards get 12 bytes. Each time an interrupt from these devices is received bytes are "freed" dynamically based on the amount of data. Changing these from the default values will have no effect on mouse and keyboard latency.

### Csrss Priority
- Csrss.exe is a critical system process responsible for things like loading assemblies. For some reason a tweak has gone around to change the priority class of this process. Changing the priority class for any process is a bad idea but especially csrss.exe since its a critical process meaning a crash will cause a BSOD to occur. Learn More about why changing priorities is a bad idea [Here](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities#priority-class)
