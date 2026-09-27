# Document 01: Lab Setup

## Where We Are

You have read Document 00 and you understand what this curriculum covers. You know you will be building C# programs that evade Windows Defender. You know the lab has two virtual machines on an isolated network. You have not installed anything yet.

At this point you need:
- A host computer with at least 16 GB RAM and 100 GB free disk space
- A processor that supports hardware virtualization
- An internet connection to download the required software

## Why This Is Next

Before you write any code, you need a working lab. Every loader in this curriculum will be compiled on a Windows 11 VM and tested against a real Windows Defender installation. The shellcode payloads will be generated on a Kali Linux VM. The two VMs talk to each other over an isolated virtual network.

If your lab is not set up correctly, nothing else in this curriculum will work. A wrong network setting means your shellcode cannot call back to Kali. A missing tool means you cannot compile or test your loaders. This document gets everything working before you touch any C# code.

## How This Works

A virtual machine (VM) is a simulated computer that runs inside your real computer. Your real computer is called the host, and the simulated computer is called the guest. VMware Workstation Pro is the software that creates and manages these virtual machines.

You will create two VMs:
- A Windows 11 Pro VM that acts as the target machine (this is the machine you are attacking)
- A Kali Linux VM that acts as the attacker machine (this is where you generate payloads and receive connections)

Both VMs will be on the same virtual network (192.168.10.0/24) so they can communicate with each other. This network is isolated from the internet and from your host machine's real network, so nothing you do in the lab leaks out.

## What Defender Does

Windows Defender is the antivirus built into Windows 11. It does these things:
- **Real-time file scanning:** Every time a file is created, downloaded, or modified, Defender scans it
- **Cloud-based analysis:** When Defender sees something suspicious, it sends a hash (a fingerprint of the file) to Microsoft's cloud servers for additional analysis
- **Memory scanning:** Defender periodically scans process memory for known malicious patterns
- **Behavior monitoring:** Defender watches what programs do at runtime (which APIs they call, what memory they allocate)
- **AMSI integration:** Defender scans scripts (PowerShell, VBScript, JavaScript) before they run
- **ETW telemetry consumption:** Defender receives telemetry events from running processes

Throughout this curriculum, Defender stays fully enabled with all of these protections active. You will learn to write code that bypasses each of these layers.

## The Evasion Technique

There is no evasion technique in this document. This is about building the lab infrastructure. The evasion starts in Document 05 when you build your first shellcode loader.

## Getting the Loader Onto the Target

This section does not apply to Document 01. There is no loader yet.

## Setting Up VMware Workstation Pro

### Step 1: Download VMware

VMware Workstation Pro is free for personal use. Download it from the official VMware website. Install it on your host machine with default settings.

After installation, open VMware Workstation Pro. You should see the main window with options to create new virtual machines.

### Step 2: Verify Virtualization Is Enabled

Your host machine's processor needs to have hardware virtualization enabled in the BIOS/UEFI settings. This is usually called "Intel VT-x" or "AMD-V" depending on your processor.

To check if virtualization is enabled:
1. Open Task Manager on your host (Ctrl + Shift + Esc)
2. Click the Performance tab
3. Click CPU
4. Look for "Virtualization: Enabled" in the bottom right

If it says "Disabled", you need to restart your computer, enter the BIOS/UEFI settings (usually by pressing F2, Del, or F12 during boot), find the virtualization setting, and enable it.

## Setting Up the Windows 11 VM

### Step 1: Download Windows 11 Pro ISO

Go to Microsoft's website and download the Windows 11 ISO file. Choose the 64-bit version. The ISO file is about 5 GB.

### Step 2: Create the VM

In VMware Workstation Pro:
1. Click "Create a New Virtual Machine"
2. Select "Custom (advanced)" and click Next
3. For hardware compatibility, select the latest version and click Next
4. Select "Installer disc image file (iso)" and browse to the Windows 11 ISO
5. Click Next through the Microsoft Easy Install screen
6. Set the VM name to "Win11-Target" and choose a location to store it
7. Set the number of processors to 2 and cores per processor to 2
8. Set RAM to 4096 MB (4 GB) minimum, 8192 MB (8 GB) if you have enough host RAM
9. For network, select "Use host-only networking" (this creates the isolated network)
10. Accept default disk settings but set the disk size to 60 GB
11. Click Finish

### Step 3: Install Windows 11

Power on the VM and follow the Windows 11 installation:
1. Select your language and region
2. Click "Install now"
3. When asked for a product key, click "I don't have a product key"
4. Select "Windows 11 Pro"
5. Accept the license terms
6. Choose "Custom: Install Windows only"
7. Select the 60 GB drive and click Next
8. Wait for installation to complete (15-30 minutes)

During the out-of-box setup:
1. When asked to connect to the internet, choose "I don't have internet" (this lets you create a local account)
2. Choose "Continue with limited setup"
3. Set the username to: **kimjongun**
4. Set a password you will remember
5. Skip all the optional Microsoft services

### Step 4: Install VMware Tools

After Windows 11 is installed and you are logged in:
1. In VMware, go to VM > Install VMware Tools
2. Open File Explorer in the Windows VM
3. Navigate to the DVD drive (usually D:)
4. Run the VMware Tools installer
5. Accept defaults and restart

VMware Tools gives you better display resolution, clipboard sharing between host and guest, and drag-and-drop file support. It makes the VM much easier to use.

### Step 5: Update Windows

Open Settings > Windows Update and install all available updates. Restart when prompted. Repeat until no more updates are available. This is critical because we want the latest Defender definitions and the latest Windows security features active.

### Step 6: Verify Defender Is Active

Open Windows Security (click the shield icon in the system tray or search for "Windows Security"):
1. Virus & threat protection: Should show "Real-time protection is on"
2. Cloud-delivered protection: Should be on
3. Automatic sample submission: Should be on
4. Click "Check for updates" under "Virus & threat protection updates" and install any available

Confirm that all settings match the default configuration. Do not change anything.

### Step 7: Install Visual Studio 2022

1. Open Edge browser in the Windows VM
2. Go to visualstudio.microsoft.com
3. Download Visual Studio 2022 Community (free)
4. Run the installer
5. When the workload selection screen appears, check these workloads:
   - **.NET desktop development** (this installs C# and the .NET SDK)
6. Click Install (this takes 10-30 minutes depending on your connection)

After installation, open Visual Studio to confirm it works. You can close it after the initial setup completes.

### Step 8: Verify .NET SDK

Open a command prompt (cmd) or PowerShell in the Windows VM and run:

```
dotnet --version
```

You should see a version number like 8.0.x or later. If dotnet is not recognized, the .NET SDK did not install correctly. Reinstall Visual Studio with the .NET desktop development workload.

### Step 9: Set a Static IP

Open Settings > Network & Internet > Ethernet:
1. Click the network adapter
2. Click Edit next to IP assignment
3. Change from Automatic (DHCP) to Manual
4. Enable IPv4
5. Set these values:
   - IP address: **192.168.10.100**
   - Subnet mask: **255.255.255.0**
   - Gateway: leave blank (the lab has no gateway)
   - DNS: leave blank
6. Click Save

## Setting Up the Kali Linux VM

### Step 1: Download Kali Linux

Go to kali.org/get-kali and download the latest Kali Linux ISO (64-bit). The file is about 3-4 GB.

### Step 2: Create the VM

In VMware Workstation Pro:
1. Click "Create a New Virtual Machine"
2. Select "Custom (advanced)"
3. Select "Installer disc image file (iso)" and browse to the Kali ISO
4. Set the VM name to "Kali-Attacker"
5. Set processors to 2 and cores to 2
6. Set RAM to 4096 MB (4 GB)
7. For network, select "Use host-only networking" (same network as the Windows VM)
8. Set disk size to 40 GB
9. Click Finish

### Step 3: Install Kali

Power on the VM and follow the Kali installation:
1. Select "Graphical install"
2. Choose your language and region
3. Set hostname to "kali"
4. Set domain to blank
5. Set the full name and username to "kali"
6. Set a password
7. Partitioning: use "Guided - use entire disk" and accept defaults
8. When asked about software selection, keep the default desktop environment
9. Install GRUB to the main drive
10. Wait for installation to complete

### Step 4: Set a Static IP

After booting into Kali, open a terminal and set the static IP:

```bash
sudo nano /etc/network/interfaces
```

Add these lines (or modify the existing interface entry):

```
auto eth0
iface eth0 inet static
    address 192.168.10.200
    netmask 255.255.255.0
```

Save and exit (Ctrl+X, Y, Enter), then restart networking:

```bash
sudo systemctl restart networking
```

Note: The interface name might be different on your system. Run `ip link show` to see the actual interface name. If it shows something like `ens33` or `ens160` instead of `eth0`, use that name in the configuration.

### Step 5: Install Required Tools

Most of these are pre-installed on Kali, but verify each one:

```bash
# Check msfvenom (part of Metasploit)
msfvenom --version

# Check python3
python3 --version

# Check smbclient
smbclient --version

# If any are missing, install them:
sudo apt update
sudo apt install -y metasploit-framework python3 smbclient
```

## Testing the Network Connection

### From Kali, ping Windows:

```bash
ping 192.168.10.100
```

### From Windows, ping Kali:

Open cmd and run:
```
ping 192.168.10.200
```

Both pings should succeed. If they do not:
1. Verify both VMs are using the same host-only network in VMware
2. Verify the static IPs are set correctly
3. On the Windows VM, check if the Windows Firewall is blocking pings. If it is, open Windows Defender Firewall > Advanced Settings > Inbound Rules > find "File and Printer Sharing (Echo Request - ICMPv4-In)" and enable it
4. Do NOT disable the Windows Firewall entirely. Only enable the ICMP rule.

## Testing File Transfer

You will need to transfer compiled loaders from Kali to Windows (or vice versa) throughout this curriculum. Test file transfer now to confirm it works.

### Method 1: Python HTTP Server (Kali to Windows)

On Kali, create a test file and start a web server:

```bash
echo "test file transfer" > /tmp/test.txt
cd /tmp
python3 -m http.server 8080
```

On Windows, open a browser and go to:
```
http://192.168.10.200:8080/test.txt
```

If the file downloads, the transfer method works. Stop the Python server with Ctrl+C.

Note: Windows Defender will scan downloaded files. This is expected and intentional. For this test file, Defender will not flag it. When you transfer actual loaders later, the way you get them onto the target without Defender flagging them will be covered in each document.

### Method 2: SMB Share (Windows to Kali)

On Windows, create a shared folder:
1. Create a folder called `C:\Share`
2. Right-click it > Properties > Sharing > Share
3. Add "Everyone" with Read/Write permissions
4. Click Share

On Kali, access the share:
```bash
smbclient //192.168.10.100/Share -U kimjongun
```

Enter the Windows password when prompted. You should see an `smb: \>` prompt where you can use `put` and `get` commands to transfer files.

## Teaching the Code

There is no code to teach in this document. The lab setup is all infrastructure. Code starts in Document 02.

## Compilation and Execution

No compilation in this document. To verify that the build toolchain works, open a command prompt on the Windows VM and run:

```
mkdir C:\Users\kimjongun\Desktop\TestProject
cd C:\Users\kimjongun\Desktop\TestProject
dotnet new console -n HelloTest
cd HelloTest
dotnet run
```

You should see "Hello, World!" printed. This confirms that the .NET SDK is installed and working. You can delete the TestProject folder after this test.

## Confirming Success

Your lab is ready when all of the following are true:

- [ ] Windows 11 VM is running with static IP 192.168.10.100
- [ ] Windows Defender is fully enabled with real-time protection, cloud protection, and auto-updates
- [ ] Visual Studio 2022 Community is installed
- [ ] `dotnet --version` returns 6.0 or later
- [ ] Kali Linux VM is running with static IP 192.168.10.200
- [ ] `msfvenom --version` works on Kali
- [ ] `python3 --version` works on Kali
- [ ] Windows can ping Kali (192.168.10.200)
- [ ] Kali can ping Windows (192.168.10.100)
- [ ] File transfer works using at least one method (Python HTTP or SMB)
- [ ] `dotnet new console` and `dotnet run` works on Windows

## What Was Gained

You now have a complete lab environment for the rest of this curriculum. You have:
- A Windows 11 target with Defender fully active, exactly matching what you would find in a real organization
- A Kali attacker machine with all the tools needed to generate payloads
- Network connectivity between the two machines
- A working C# build toolchain (Visual Studio + .NET SDK) ready to compile loaders
- Verified file transfer between the machines

This means you can write C# code on the Windows VM, compile it, run it, and see how Defender reacts. You can generate shellcode on Kali, transfer it to Windows, and test whether your loaders can execute it without getting caught.

## Common Threats and Variations

### Variation 1: Using VirtualBox Instead of VMware

VirtualBox is a free alternative to VMware. It works for this curriculum, but some features like shared folders and clipboard sharing are less reliable. If you use VirtualBox, create a "Host-only Adapter" for the isolated network and assign the same static IPs. The rest of the curriculum works the same way regardless of which hypervisor you use.

### Variation 2: Using Physical Machines Instead of VMs

If you have two physical computers, you can connect them to an isolated switch (no internet connection) and use them as target and attacker. This is closer to a real engagement. The disadvantage is that if something goes wrong on the Windows machine, you cannot easily roll it back to a clean snapshot like you can with a VM.

### Variation 3: Using WSL Instead of a Kali VM

Windows Subsystem for Linux (WSL) on your host machine could replace the Kali VM for generating shellcode and running tools. However, WSL shares the host network, so it is not isolated. For learning purposes, a separate Kali VM is safer and more realistic.

## Detection and Defense (Blue Team Perspective)

This document covers lab setup, not attack techniques, so there are no specific defenses to discuss. However, there are general security practices relevant to the lab:

**Snapshot your VMs.** Before you begin any testing, take a snapshot of both the Windows and Kali VMs in their clean, freshly-set-up state. If anything goes wrong during testing (accidental malware execution, system corruption), you can revert to the clean snapshot in seconds.

**Keep the lab network isolated.** The host-only network in VMware ensures that nothing in your lab reaches the internet or your real network. If you accidentally set the VMs to NAT or bridged networking, your test shellcode could reach real systems. Always verify the network setting is host-only.

**Update Defender regularly.** Before each testing session, check for Defender updates. Signatures change frequently, and you want your lab to match real-world conditions as closely as possible.

## What Comes Next

Start Document 02 (lab/materials/02_c_sharp_basics.md). It teaches you C# programming from scratch, using security-focused examples instead of boring textbook exercises. By the end of Document 02, you will know enough C# to understand every loader in this curriculum.
