# PingPlotterPS51


[![Hits](https://hits.sh/github.com/MaxITService/Ping-Plotter-PS51.svg?style=flat)](https://hits.sh/github.com/MaxITService/Ping-Plotter-PS51/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A PowerShell 5.1+ script that functions as a "ping plotter" analog. It tests connectivity to a target host, logs results, displays a summary, and can perform diagnostic actions during outages.
<p><b><span style="color:green;">No learning curve - just run the script and follow the prompts!</span></b></p>
**BETA STATUS NOTICE**: This script is currently in beta. While it has been tested, it may contain bugs or unexpected behaviors. Please report any issues you encounter.

## Features

- Performs repeated connectivity tests (ICMP or TCP) to a specified target host
- Configurable via interactive prompts or JSON configuration file
- Detects and logs "Hard Outages" (consecutive failed tests)
- Optional "Soft Outages" detection (consecutive high-latency ICMP pings)
- Automatic diagnostic actions during outages:
  - Log ipconfig output
  - Ping alternative hosts
  - Execute custom diagnostic scripts
- Detailed logging with timestamps
- Summary reports at end of sessions
- Full Windows PowerShell 5.1+ compatibility

## Requirements

- Windows PowerShell 5.1 or later
- Windows operating system

## Usage

### Interactive Mode
```powershell
.\Get-Ping-Plot-PS51.ps1
```
This will prompt you for all configuration options.

### Configuration File Mode
```powershell
.\Get-Ping-Plot-PS51.ps1 -ConfigurationFile "my_ping_config.json"
```

### Example Configuration File
See documentation in the script header for a detailed example of the JSON configuration format.

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Promo (My other stuff!)
Check out my Free Extension for Web AI chats to quickly reuse your prompts:

[![Check out my Free Extension for Web AI chats to quickly reuse your prompts](https://github.com/MaxITService/ChatGPT-Quick-Buttons-for-your-text/raw/master/Promo/promo440_280.png)](https://chromewebstore.google.com/detail/oneclickprompts/iiofmimaakhhoiablomgcjpilebnndbf?authuser=1)

[OneClickPrompts on Chrome Web Store](https://chromewebstore.google.com/detail/oneclickprompts/iiofmimaakhhoiablomgcjpilebnndbf?authuser=1) | 
[it is open source](https://github.com/MaxITService/ChatGPT-Quick-Buttons-for-your-text)

Add AI to your PowerShell that reads what you have in screen buffer:

[Console2AI](https://github.com/MaxITService/Console2AI) (it is open source) Get AI to your PowerShell 