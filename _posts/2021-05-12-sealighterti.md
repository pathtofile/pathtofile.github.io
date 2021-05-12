---
layout: post
title:  "Getting Threat-Intelligence the dodgy way"
date:   2021-05-12 12:00:00 +0000
---
 
# tl;dr
I've released a tool called [Sealighter-TI](https://github.com/pathtofile/SealighterTI) that uses research from [Alex Ionescu](https://twitter.com/aionescu) and [James Forshaw](https://twitter.com/tiraniddo), plus code from [Clément Labro's](https://twitter.com/itm4n) project [PPLDump](https://github.com/itm4n/PPLdump), to get events
from the protected `Microsoft-Windows-Threat-Intelligence` ETW provider without a signed driver to putting Windows into Test Signing mode.
 
# Protecting AntiMalware Services (for real this time)
A few months ago I wrote [a blog](https://blog.tofile.dev/2020/12/16/elam.html) about the `Microsoft-Windows-Threat-Intelligence` ETW provider, and how only processes started at least as `Protected Process Light Anti-Malware` (or PPL-AM) can receive events from it. I made a tool called [PPLRunner](https://github.com/pathtofile/PPLRunner) that would allow you to run any program as PPL, which in the blog I used to run my ETW Tracer [Sealighter](https://github.com/pathtofile/sealighter) to handle the `Threat-Intelligence` events.
 
But while PPLRunner served as a useful example of how to legitimately start a PPL Process, it would only work if Windows was put into either a Debug or 'Test Signing' mode. This is because to officially be able to run your code as PPL-AM you need to submit an ELAM or 'Early Launch Anti Malware' Driver to Microsoft to [review and sign](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-submission). Being an open source project I made instead of getting sleep, I had 0 interest in doing anything so formal. 
 
But running Windows in debug or test signing mode might alter the behaviour of the malware or other programs, as they may (rightfully) notice and believe they are being observed, and not running on a 'real' system. So I wanted to see if there was other ways to get code running as PPL, legitimate or otherwise.
 
 
# The non-secure security boundary
Back in 2018 [Alex Ionescu](https://twitter.com/aionescu) and [James Forshaw](https://twitter.com/tiraniddo) presented a [series of talks](http://publications.alex-ionescu.com/Recon/Recon%202018%20-%20Unknown%20Known%20DLLs%20and%20other%20code%20integrity%20trust%20violations.pdf), and [blogs](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html), covering many ways you could trick Windows into illegitimately running arbitrary code at the PPL level.
 
A number of these techniques remain unpatched to this day, mostly due to the fact that Microsoft [don't consider Admin-PPL](https://bugs.chromium.org/p/project-zero/issues/detail?id=1336) a security boundary. Despite its purpose being a security boundary to protect certain processes from malicious SYSTEM-level access.
 
Then a few weeks ago [Clément Labro](https://twitter.com/itm4n) released [PPLDump](https://github.com/itm4n/PPLdump). PPLDump uses one of the unpatched DLL hijack techniques Alex and James covered to launch PPL-elevated `services.exe` and trick it into loading an arbitrary DLL. This project and exploit is really neat, and I encourage you to also read Clément's [blog](https://itm4n.github.io/lsass-runasppl/) about the project, as well as [the one from James](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html) where the technique was first discussed.
 
 
# Taking the red and turning blue
PPLDump is an offensive tool that is used to dump credentials and memory from PPL protected processes such as `lsass.exe`. But I wanted to use the code for defensive purposes - I wanted to use Clément's code to log the `Threat-Intelligence` ETW Provider without the need for a signed driver, or having to put Windows into Test Signing mode.
 
It turns out this was a super-smooth process. Clément's code was well laid out that forking it and altering the code it injects was straight forward, so I only had to make some minor changes to enable it to load a DLL containing Sealighter.
 
# Hook, line, and threading
One small hurdle I had to overcome was the while the exploit and Clément's code got a DLL loaded into the PPL Process, only the `DLLMain` would be called before the process exited. While this was fine for Clément's purposes of dumping process memory, doing anything complex inside of DLLMain is [heavily discouraged](https://devblogs.microsoft.com/oldnewthing/20040127-00/?p=40873), as you have no control over what DLLs get loaded in what order, which means if you attempt to call a function from another dll (such as `ntdll`) to risk crashing or deadlocking the process.
 
Sealighter makes use of COM, threading, and lots of other stuff that would make Raymond Chen nervous, so I made use of the [Detours](https://github.com/microsoft/Detours/) hooking library from Microsoft to hook the executable's `main()` entrypoint function, 'elevating' our arbitrary code execution from running inside of a `DLLMain` to running once all DLLs had been loaded and all PE setup has occurred, right before the PE's main entrypoint. Using Detours is super simple, the relevant code basically looks like this:
```c++
static int (WINAPI* TrueEntryPoint)(VOID);
int WINAPI HookedEntryPoint(VOID);
 
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Find the PEs Entrypoint and hook it
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        TrueEntryPoint = (int (WINAPI*)(VOID))DetourGetEntryPoint(NULL);
        DetourAttach(&(PVOID&)TrueEntryPoint, HookedEntryPoint);
        DetourTransactionCommit();
    } else if (dwReason == DLL_PROCESS_DETACH) {
        // Remove hook
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueEntryPoint, HookedEntryPoint);
        DetourTransactionCommit();
    }
    return TRUE;
}
 
int WINAPI HookedEntryPoint(VOID); {
    // You're now running as if you are the wmain() function of the PE
    ...
    // Once finished, call the real wmain() function
    return TrueEntryPoint();
}
```
 
 
# Introducing: Sealighter-TI
 
The completed project is now on GitHub, which I’ve called [Sealighter-TI](https://github.com/pathtofile/SealighterTI).
 
Sealighter-TI will first use Alex's/James's/Clément's DLL-hijack exploit to start a PPL-elevated `services.exe` with a custom DLL loaded into it, which will run an ETW Trace of the `Threat-Intelligence` Provider and log the events to the Windows Event Log, to be viewed and read from non-PPL processes like PowerShell:
 
![Picture of Sealighter injected into a ppl process](/assets/SealighterTI_Running.png)
 
![Picture of Sealighter injected into a ppl process](/assets/SealighterTI_EventLog.png)
 
Sealighter-TI works without the need to sign any driver, and without having to put Windows in debug or test signing mode. The exploit it relies on could be fixed by Microsoft, and this would break Sealighter-TI, but it's currently been 3 years without it being fixed, so Sealighter-TI may work for a while yet. Unless PPLDump elevates the bug in Microsoft's queue, in which case it may need to be replaced with one of the other unpatched Admin->PPL exploits.
 
# Further Reading
To learn more about PPL, I highly recommend reading these blogs and talks:
- https://www.alex-ionescu.com/?p=97
- https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html
- https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/
- http://publications.alex-ionescu.com/Recon/Recon%202018%20-%20Unknown%20Known%20DLLs%20and%20other%20code%20integrity%20trust%20violations.pdf

To learn more about ETW and the `Threat Inteligence` ETW Provider, I reccomend these blogs:
- https://blog.redbluepurple.io/windows-security-research/kernel-tracing-injection-detection
- https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
- https://blog.tofile.dev/2020/12/16/elam.html
