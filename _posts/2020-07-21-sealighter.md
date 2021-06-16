---
layout: post
title:  "Introducing Sealighter - Sysmon-Like research tool for ETW"
date:   2020-07-21 12:00:00 +0000
cat:    ETW
---

After some code cleanup, I'm open sourcing my Event Tracing for Windows (ETW) research tool, called [Sealighter](https://github.com/pathtofile/sealighter).

![Sealighter](/assets/sealighter.png)

# Overview
Sealighter leverages the feature-rich [Krabs ETW](https://github.com/microsoft/krabsetw) Library to enable detailed filtering and triage of ETW and WPP Providers and Events.

You can subscribe and filter multiple providers, including User mode Providers, Kernel Tracing, Tracelogging, and WPP Tracing, and output events as JSON to either stdout, a file, or the Windows Event Log (useful for high-volume traces like `FileIO`). No knowledge of the events the provider may produce, or their format, is necessary, Sealighter automatically captures and parses any events it is asked.

Events can then be parsed from JSON in Python, PowerShell, or forwarded to Splunk or ELK for further searching.

Filtering can be done on various aspects of an Event, from its ID or Opcode, to matching a property value, to doing an arbitrary string search across the entire event (Useful in Tracelogging and WPP traces or when you don't know the event structure, but have an idea of its contents). You can also chain multiple filters together, or negate the filter. You can also filter the maximum events per ID, useful to investigate a new provider without being flooded by similar events.


# Why this exists
ETW is an incredibly useful system for both Red and Blue teams. Red teams may glean insight into the inner workings of Windows components, and Blue teams might get valuable insight into suspicious activity.

A common research loop would be:
1. Identify interesting ETW Providers using `logman query providers` or Looking for Tracelogging and WPP Traces in Binaries
2. Start a Session with the interesting providers enable, and capture events whilst doing something 'interesting'
3. Look over the results, using one or more of:
   - Eyeballing each event/grepping for words you expect to see
   - Run a script in Python or PowerShell to help filter or find interesting captured events
   - Ingesting the data into Splunk or an ELK stack for some advanced UI-driven searching

Doing this with ETW Events can be difficult, without writing code to interact with and parse events from the obtuse ETW API. If you're not a strong programmer (or don't want to deal with the API), your only other options are to use a combination of older inbuilt windows tools to write to disk as binary `etl` files, then dealing with those. Tracelogging and WPP traces compounds the issues, providing almost no easy-to-find data about provider and their events.

Projects like [JDU2600's Event List ](https://github.com/jdu2600/Windows10EtwEvents) and [ETWExplorer](https://github.com/zodiacon/EtwExplorer) and give some static insight, but Providers often contain obfuscated event names like `Event(1001)`, meaning the most interesting data only becomes visible by dynamically running a trace and observing the output.


# So like SilkETW?
In a way, this plays in a similar space as FuzzySec's [SilkETW](https://github.com/fireeye/SilkETW). But While Silk is more production-ready for defenders, this is designed for researchers like myself, and as such contains a number of features that I couldn't get with Silk, mostly due to the different Library they used to power the tool. Please see [Here](docs/COMPARISION.md) for more information.

# Intended Audience
Probably someone who understands the basic of ETW, and really wants to dive into discovering what data you can glean from it, without having to write code or manually figure out how to get and parse events.

# More information and getting Started
View the documentation and get the binaries, on Github: [https://github.com/pathtofile/sealighter](https://github.com/pathtofile/sealighter)
