#repair bad tweaks by zoic
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

#global vars
$Global:currentControlSet = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet'
$Global:controlSet001 = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001'

#function to check for bad tweaks returns hastable 
function checkTweaks {
    #hashtable for tweaks
    $tweaksTable = @{}
    $tweaks = @(
        'Svc Split Threshold',
        'Bcdedit',
        'Timer Resolution',
        'Win32PrioritySeparation',
        'Tcp Auto-Tuning',
        'Prefetch',
        'Windows Error Reporting',
        'Sysmain Service',
        'Ordinary DPCs',
        'Spectre Meltdown Mitigations',
        'HPET',
        'Mouse Keyboard Queue Size',
        'Csrss Priority'
    )
    #add to hashtable
    foreach ($tweak in $tweaks) {
        $tweaksTable[$tweak] = $false
    }
    
    #check svc split threshold
    $svcSplitCurrent = Get-ItemPropertyValue -Path "registry::$currentControlSet\Control" -Name 'SvcHostSplitThresholdInKB'
    $svcSplitControl = Get-ItemPropertyValue -Path "registry::$controlSet001\Control" -Name 'SvcHostSplitThresholdInKB'
    if ($svcSplitCurrent -ne 3670016 -or $svcSplitControl -ne 3670016) {
        $tweaksTable['Svc Split Threshold'] = $true
    }

    #check bcdedit tweaks
    $bcd = bcdedit.exe
    #regEX with | for 'or'
    $values = 'useplatformclock|disabledynamictick|useplatformtick|tscsyncpolicy'
    if ($bcd -match $values) {
        $tweaksTable['Bcdedit'] = $true
    }

    #check for timer res, timer res service, islc
    #global scope for proper cleanup later
    $Global:timerRes = Get-Process -Name TimerResolution -ErrorAction SilentlyContinue
    $Global:timerResService = Get-Service -Name 'STR', 'Set Timer Resolution Service' -ErrorAction SilentlyContinue
    $Global:islc = Get-Process -Name 'Intelligent standby list cleaner ISLC' -ErrorAction SilentlyContinue

    if ($timerRes -or $timerResService -or $islc) {
        $tweaksTable['Timer Resolution'] = $true
    }


    #check win32priority 
    $controlSetP = Get-ItemPropertyValue -Path "registry::$controlSet001\Control\PriorityControl" -Name 'Win32PrioritySeparation'
    $currentControlSetP = Get-ItemPropertyValue -Path "registry::$currentControlSet\Control\PriorityControl" -Name 'Win32PrioritySeparation'
    if ($currentControlSetP -ne 38 -or $controlSetP -ne 38) {
        $tweaksTable['Win32PrioritySeparation'] = $true
    }


    #check auto-tuning 
    $autotuning = netsh interface tcp show global | Select-String 'Receive Window Auto-Tuning Level'
    if ($autotuning -notlike '*normal*') {
        $tweaksTable['Tcp Auto-Tuning'] = $true
    }

    #check prefetch
    $prefetchCurrent = Get-ItemPropertyValue -Path "registry::$currentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name 'EnablePrefetcher'
    $prefetchControl = Get-ItemPropertyValue -Path "registry::$controlSet001\Control\Session Manager\Memory Management\PrefetchParameters" -Name 'EnablePrefetcher'
    if ($prefetchCurrent -ne 3 -or $prefetchControl -ne 3) {
        $tweaksTable['Prefetch'] = $true
    }

    #check sysmain service (superfetch)
    $start = (Get-Service -Name SysMain).StartType
    if ($start -ne 'Automatic') {
        $tweaksTable['Sysmain Service'] = $true
    }


    #check ordinary dpcs
    $currentDpc = (Get-ItemProperty -Path "registry::$currentControlSet\Control\Session Manager\kernel").ThreadDpcEnable
    $controlDpc = (Get-ItemProperty -Path "registry::$controlSet001\Control\Session Manager\kernel").ThreadDpcEnable
    if ($currentDpc -eq 0 -or $controlDpc -eq 0) {
        $tweaksTable['Ordinary DPCs'] = $true
    }

    #windows error reporting
    $svcStart = (Get-Service -Name WerSvc).StartType
    $policy = (Get-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -ErrorAction SilentlyContinue).Disabled
    if ($svcStart -ne 'Manual' -or $policy -eq 1) {
        $tweaksTable['Windows Error Reporting'] = $true
    }

    #check spectre and meltdown mitigations
    $overrideCurrent = (Get-ItemProperty -Path "registry::$currentControlSet\Control\Session Manager\Memory Management").FeatureSettingsOverride
    $overrideMaskCurrent = (Get-ItemProperty -Path "registry::$currentControlSet\Control\Session Manager\Memory Management").FeatureSettingsOverrideMask
    $overrideControl = (Get-ItemProperty -Path "registry::$controlSet001\Control\Session Manager\Memory Management").FeatureSettingsOverride
    $overrideMaskControl = (Get-ItemProperty -Path "registry::$controlSet001\Control\Session Manager\Memory Management").FeatureSettingsOverrideMask
    if ($overrideCurrent -eq 3 -or $overrideMaskCurrent -eq 3 -or $overrideControl -eq 3 -or $overrideMaskControl -eq 3) {
        $tweaksTable['Spectre Meltdown Mitigations'] = $true
    }

    #check High precision event timer
    $status = (Get-PnpDevice -FriendlyName 'High precision event timer').Status
    if ($status -ne 'OK') {
        $tweaksTable['HPET'] = $true
    }

    #check mouse and keyboard queue size
    $keyboardCurrent = Get-ItemPropertyValue -Path "registry::$currentControlSet\Services\kbdclass\Parameters" -Name 'KeyboardDataQueueSize' -ErrorAction SilentlyContinue
    $mouseCurrent = Get-ItemPropertyValue -Path "registry::$currentControlSet\Services\mouclass\Parameters" -Name 'MouseDataQueueSize' -ErrorAction SilentlyContinue
    $keyboardControl = Get-ItemPropertyValue -Path "registry::$controlSet001\Services\kbdclass\Parameters" -Name 'KeyboardDataQueueSize' -ErrorAction SilentlyContinue
    $mouseControl = Get-ItemPropertyValue -Path "registry::$controlSet001\Services\mouclass\Parameters" -Name 'MouseDataQueueSize' -ErrorAction SilentlyContinue
    #if value is null that is fine too (default value 100)
    if ($keyboardCurrent) {
        if ($keyboardCurrent -ne 100) {
            $tweaksTable['Mouse Keyboard Queue Size'] = $true
        }
    }
    if ($mouseCurrent) {
        if ($mouseCurrent -ne 100) {
            $tweaksTable['Mouse Keyboard Queue Size'] = $true
        }
    }
    if ($keyboardControl) {
        if ($keyboardControl -ne 100) {
            $tweaksTable['Mouse Keyboard Queue Size'] = $true
        }
    }
    if ($mouseControl) {
        if ($mouseControl -ne 100) {
            $tweaksTable['Mouse Keyboard Queue Size'] = $true
        }
    }

    #check csrss priority
    if (Test-Path -Path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions' -ErrorAction SilentlyContinue) {
        $tweaksTable['Csrss Priority'] = $true
    }

    return $tweaksTable
}

#pass string array
function repairTweaks($tweakNames) {
    foreach ($tweak in $tweakNames) {
        #repair superfetch
        if ($tweak -eq 'Sysmain Service') {
            Set-Service -Name SysMain -StartupType Automatic
        }
        #repair threaded dpcs
        if ($tweak -eq 'Ordinary DPCs') {
            Remove-ItemProperty -Path "registry::$currentControlSet\Control\Session Manager\kernel" -Name ThreadDpcEnable -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "registry::$controlSet001\Control\Session Manager\kernel" -Name ThreadDpcEnable -Force -ErrorAction SilentlyContinue
        }
        #repair hpet
        if ($tweak -eq 'HPET') {
            Get-PnpDevice -FriendlyName 'High precision event timer' | Enable-PnpDevice -Confirm:$false
        }
        #repair mouse keyboard queue size
        if ($tweak -eq 'Mouse Keyboard Queue Size') {
            Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters' /v 'KeyboardDataQueueSize' /t REG_DWORD /d '100' /f *>$null
            Reg.exe add 'HKLM\SYSTEM\ControlSet001\Services\kbdclass\Parameters' /v 'KeyboardDataQueueSize' /t REG_DWORD /d '100' /f *>$null
            Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters' /v 'KeyboardDataQueueSize' /t REG_DWORD /d '100' /f *>$null
            Reg.exe add 'HKLM\SYSTEM\ControlSet001\Services\mouclass\Parameters' /v 'KeyboardDataQueueSize' /t REG_DWORD /d '100' /f *>$null
        }
        #repair timer res
        if ($tweak -eq 'Timer Resolution') {
            #cleanup timer res depending on which is being used
            if ($timerRes) {
                $filePath = (Get-Process -Name TimerResolution -FileVersionInfo).FileName
                Stop-Process -Name TimerResolution -Force
                Remove-Item -Path $filePath -Force
            }
            if ($timerResService) {
                $name = (Get-Service -Name 'Set Timer Resolution Service', 'STR' -ErrorAction SilentlyContinue).Name
                $serviceExePath = (Get-Process -Name SetTimerResolutionService -FileVersionInfo).FileName
                Stop-Service -Name $name -Force
                Stop-Process -Name SetTimerResolutionService -Force -ErrorAction SilentlyContinue
                sc.exe delete $name *>$null
                Remove-Item -Path $serviceExePath -Force
            }
            if ($islc) {
                $filePath = (Get-Process -Name 'Intelligent standby list cleaner ISLC' -FileVersionInfo).FileName
                Stop-Process -Name 'Intelligent standby list cleaner ISLC' -Force
                Remove-Item -Path $filePath -Force
            }
        }
        #repair svc split threshold
        if ($tweak -eq 'Svc Split Threshold') {
            Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control' /v 'SvcHostSplitThresholdInKB' /t REG_DWORD /d '3670016' /f *>$null
            Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control' /v 'SvcHostSplitThresholdInKB' /t REG_DWORD /d '3670016' /f *>$null
        }
        #repair bcdedit 
        if ($tweak -eq 'Bcdedit') {
            bcdedit.exe /deletevalue useplatformclock *>$null
            bcdedit.exe /deletevalue disabledynamictick *>$null
            bcdedit.exe /deletevalue useplatformtick *>$null
            bcdedit.exe /deletevalue tscsyncpolicy *>$null
        }
        #repair prefetch
        if ($tweak -eq 'Prefetch') {
            Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' /v 'EnablePrefetcher' /t REG_DWORD /d '3' /f *>$null
            Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters' /v 'EnablePrefetcher' /t REG_DWORD /d '3' /f *>$null
        }
        #repair win32priorityseperation
        if ($tweak -eq 'Win32PrioritySeparation') {
            Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\PriorityControl' /v 'Win32PrioritySeparation' /t REG_DWORD /d '38' /f *>$null
            Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl' /v 'Win32PrioritySeparation' /t REG_DWORD /d '38' /f *>$null
        }
        #repair tcp autotuning
        if ($tweak -eq 'Tcp Auto-Tuning') {
            netsh.exe interface tcp set global autotuninglevel=normal *>$null
        }
        #repair spectre meltdown
        if ($tweak -eq 'Spectre Meltdown Mitigations') {
            Remove-ItemProperty -Path "registry::$currentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "registry::$controlSet001\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "registry::$currentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "registry::$controlSet001\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Force -ErrorAction SilentlyContinue
        }
        #repair windows error reporting
        if ($tweak -eq 'Windows Error Reporting') {
            Set-Service -Name WerSvc -StartupType Manual -Force 
            Remove-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Force -ErrorAction SilentlyContinue
        }
        #repair csrss priority
        if ($tweak -eq 'Csrss Priority') {
            Remove-Item -Path 'registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions' -Recurse -Force
        }

    }
}

Write-Host 'Checking For Bad Tweaks...'
$getTweaks = checkTweaks
$trueCount = 0
$badTweaksName = @()
foreach ($tweak in $getTweaks.GetEnumerator()) {
    #if bad tweak is found 
    if ($tweak.Value) {
        $badTweaksName += $tweak.Key
        Write-Host "[$($tweak.Key)]" -ForegroundColor Red
    }
    else {
        $trueCount++
        Write-Host "[$($tweak.Key)]" -ForegroundColor Green
    }
}
#no bad tweaks found
if ($trueCount -eq $getTweaks.Count) {
    Write-Host 'No Bad Tweaks Found!'
    $input = Read-Host 'Press ANY Key to Exit...'
    if ($input) {
        exit
    }
}
else {
    #use choice cmdlet
    choice.exe /c yn /n /m 'Press Y to Repair Bad Tweaks (N to SKIP)'
    if ($LASTEXITCODE -eq 1) {
        repairTweaks $badTweaksName
        #call check tweaks to confirm they have been repaired
        $getTweaks = checkTweaks
        $trueCount = 0
        $badTweaksName = @()
        foreach ($tweak in $getTweaks.GetEnumerator()) {
            #if bad tweak is found 
            if ($tweak.Value) {
                $badTweaksName += $tweak.Key
            }
            else {
                $trueCount++
            }
        }
        if ($trueCount -eq $getTweaks.Count) {
            Write-Host 'Tweaks Repaired Successfully!'
            $input = Read-Host 'Press ANY Key to Exit...'
            if ($input) {
                exit
            }
        }
        else {
            Write-Host 'Tweaks Not Repaired:'
            foreach ($name in $badTweaksName) {
                Write-Host "[$($name)]" -ForegroundColor Red
            }
        }
    }
    else {
        exit
    }
}