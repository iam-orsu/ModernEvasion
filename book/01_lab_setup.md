# Document 01: Lab Setup

## Where We Are

You have read Document 00 and you understand the full picture: why C# is the right language for Windows evasion, how Defender's 6 detection layers work, what each of the 8 loaders does, and how this curriculum connects to real red team jobs. You have not installed or set up anything yet.

At this point you know:
- C# gives you direct access to Windows functions through P/Invoke
- Defender uses static file scanning, cloud analysis, AMSI, API hooks, ETW logging, and behavioral analysis
- You will build 8 loaders, each targeting a specific detection layer
- You need three virtual machines: a Windows 11 dev box for compiling loaders, a Windows 11 target for running loaders against Defender, and a Kali Linux attacker for generating shellcode and running listeners

You need a host machine with at least 24 GB RAM, 150 GB free disk, and a CPU with virtualization support (Intel VT-x or AMD-V).

## Why This Is Next

Every loader in this curriculum compiles on a dedicated dev box (a Windows 11 machine with Visual Studio installed) and then gets transferred to a separate Windows 11 target machine that has Defender enabled. The shellcode payloads come from msfvenom on a Kali machine. All three machines communicate over an isolated network where you can test without affecting your real network or the internet.

If the lab is wrong, nothing else works. A wrong network configuration means your shellcode's reverse connection cannot reach Kali, so you will think your loader failed when actually the network is broken. A missing .NET SDK on the dev box means you cannot compile. An outdated Defender on the target means you are testing against old signatures, and your loaders will work in the lab but fail on a real target. This document gets the infrastructure right so every subsequent document works the first time.

The lab also teaches you something that matters on real engagements: the three-machine workflow. On a real red team engagement, you have your development machine (where you build your tools and compile payloads), your attacker machine (where you generate shellcode, run listeners, and receive connections), and the target machine (the client's system you are testing). You never compile your malware on the target. You build it on your own dev machine, transfer only the final binary to the target, and run it there. The lab mirrors this exactly. Learning to work across three machines, transfer files, and manage connections is an operational skill you will use on every engagement.

## How This Works

### What a Virtual Machine Is

A virtual machine (VM) is a software simulation of a complete computer. Your real computer (the host) runs software called a hypervisor that creates one or more virtual computers (guests) inside it. Each guest has its own operating system, its own hard drive (stored as a file on the host), its own network adapter (simulated by the hypervisor), and its own share of RAM. The guest operating system does not know it is virtual. It runs exactly like a real computer.

VMware Workstation Pro is the hypervisor you will use. It creates a layer between your host hardware and the guest operating systems, giving each guest its own isolated environment. The reason we use VMs instead of real machines is control: you can snapshot a VM at any point and restore it to that exact state later. A snapshot saves the entire state of the VM, including all files, all running programs, all settings, everything. If a loader does something unexpected, you restore the snapshot and you are back to exactly where you were. On a physical machine, you would need to reinstall the OS.

### What a Host-Only Network Is

VMware lets you create virtual networks that exist only inside the hypervisor. A host-only network connects VMs to each other but does not connect them to the internet or to your host machine's real network. This isolation is critical:

- Your shellcode payloads make network connections (reverse shells call back to the attacker machine). On a host-only network, those connections stay inside the hypervisor. If you accidentally used a bridged network (which connects to your real network), your shellcode could try to connect to real machines on your network.
- Defender's cloud protection sends file hashes to Microsoft for analysis. On a host-only network with no internet, cloud protection cannot reach Microsoft. This is actually a realistic scenario because many enterprise networks restrict outbound connections. However, for the most accurate testing, you can optionally give the target VM internet access through a NAT adapter for Defender updates only, then switch back to host-only for testing.
- Nothing you do in the lab affects anything outside the lab. This is a safety boundary that protects your real environment.

All three VMs will be on the network 192.168.10.0/24. That means all IP addresses start with 192.168.10 and the subnet mask is 255.255.255.0. The /24 means the first 24 bits of the address are the network portion, which is a standard notation you will see everywhere in networking. The dev box gets 192.168.10.150, the target gets 192.168.10.100, and Kali gets 192.168.10.200.

### What Defender's Default Configuration Looks Like

When you install Windows 11 and do not change any security settings, Defender runs with these protections:

- **Real-time protection:** Every time a file is created, downloaded, or modified on the hard drive, Defender scans it immediately. When your compiled loader .exe lands on the hard drive, Defender scans it before you can even run it.
- **Cloud-delivered protection:** When Defender sees a file it does not recognize, it sends a hash (a unique number calculated from the file's bytes, like a fingerprint) to Microsoft's cloud for analysis. The cloud has machine learning models and a larger signature database. If the cloud says the file is malicious, Defender blocks it.
- **Automatic sample submission:** Defender can send the actual file (not just the hash) to Microsoft for deep analysis. This is enabled by default.
- **Tamper protection:** Prevents programs from modifying Defender's settings, disabling its services, or patching its DLL files. This is why our AMSI bypass patches amsi.dll inside our own program's RAM space rather than trying to modify Defender itself.
- **Controlled folder access:** Protects common folders (Documents, Desktop, etc.) from unauthorized modifications by unknown programs.
- **Exploit protection:** Enforces security features like DEP (Data Execution Prevention, which stops the CPU from running code in RAM that is marked as data-only), ASLR (Address Space Layout Randomization, which loads DLL files at random RAM addresses each time the computer boots), and CFG (Control Flow Guard, which prevents code from jumping to unexpected addresses).

All of these stay at their default settings throughout the curriculum. You will not change, disable, or weaken any of them. This matters because when you test a loader and it works, you know it works against real production security. If you disabled cloud protection or real-time scanning, your results would not reflect reality.

## What Defender Does

During lab setup specifically, Defender does two things that affect you:

1. **It scans downloaded files.** When you download Visual Studio, .NET SDK, or any other installer, Defender scans the downloaded file. This is normal and will not interfere with your setup.

2. **It may quarantine compiled loaders later.** When you compile a loader later in the curriculum, Defender may quarantine the resulting .exe or .dll if it detects it as malicious. This is expected. Defender detecting your loader is not a problem. It is information that tells you your loader needs more evasion work. During lab setup, this is not relevant because you are not compiling any loaders yet.

## The Evasion Technique

There is no evasion technique in this document. Lab setup is infrastructure work. Evasion begins in Document 05 when you build your first shellcode loader. However, the lab setup decisions you make here directly affect how your loaders will behave:

- The host-only network means your reverse shell payloads will connect to 192.168.10.200 (Kali). If the network is misconfigured, the shells will not connect.
- The Defender configuration determines what your loaders need to bypass. If you weakened Defender, your loaders would work in the lab but fail in the real world.
- The .NET SDK version determines which C# features are available. We target .NET 6 or later because it supports the unsafe code blocks and Marshal operations our loaders need.

## Getting the Loader Onto the Target

No loader exists yet. This section applies starting from Document 05. For now, you need to set up file transfer between Kali and Windows so it is ready when you need it.

The two file transfer methods you will use throughout this curriculum are:

1. **Python HTTP server on Kali:** You run `python3 -m http.server 8080` on Kali, which starts a web server that serves files from the current directory. On Windows, you download files using a browser or PowerShell's `Invoke-WebRequest`. This is how most red team engagements deliver initial payloads, through HTTP/HTTPS downloads.

2. **SMB file sharing:** Windows natively supports SMB (Server Message Block) file shares. SMB is a protocol (a set of rules for communication) that Windows uses for sharing files and folders over a network. You create a shared folder on Windows, and Kali accesses it using `smbclient`. This is bidirectional, meaning you can upload files from Kali to Windows and download files from Windows to Kali. SMB is useful when you need to quickly move files back and forth during testing.

Both methods are set up and tested in this document so they are ready when loaders start getting compiled.

## Teaching the Code

There is no code to teach in this document. This is infrastructure setup. The first code appears in Document 02 (C# Basics).

However, you will run one verification command at the end to confirm the .NET SDK is working:

```csharp
using System;

class Program
{
    static void Main()
    {
        Console.WriteLine("Build toolchain is working.");
    }
}
```

This program does nothing interesting. It exists only to verify that the `dotnet` command can compile and run C# code on your dev box (ammulu, 192.168.10.150).

## Setting Up VMware Workstation Pro

### Step 1: Download and Install VMware

VMware Workstation Pro became free for personal use in 2024. Download it from the official VMware website (now part of Broadcom). Run the installer on your host machine and accept the default settings.

After installation, open VMware Workstation Pro. You will see the home screen with options to create virtual machines.

### Step 2: Verify Hardware Virtualization

VMware requires hardware virtualization (Intel VT-x or AMD-V) enabled in your host machine's BIOS/UEFI. The BIOS is a program stored on your motherboard that runs before your operating system loads. It controls basic hardware settings. Without virtualization enabled in the BIOS, VMs will be extremely slow or will not start at all.

To check if virtualization is enabled on your host:
1. Open Task Manager (Ctrl + Shift + Esc)
2. Click the Performance tab
3. Click CPU
4. In the bottom-right section, look for "Virtualization: Enabled"

If it says "Disabled":
1. Restart your computer
2. Enter BIOS/UEFI settings (the key varies by manufacturer: F2, Del, F10, F12, or Esc during boot. Your motherboard manual or a quick search for your model will tell you which key)
3. Find the virtualization setting (it is usually under CPU Configuration, Advanced, or Security)
4. Enable it (the setting name varies: "Intel Virtualization Technology", "Intel VT-x", "AMD-V", "SVM Mode")
5. Save and exit BIOS

### Step 3: Create the Host-Only Network

Before creating VMs, set up the isolated network:
1. In VMware, go to Edit > Virtual Network Editor
2. Click "Change Settings" (requires admin permissions)
3. You should see a host-only network (usually VMnet1). If not, click "Add Network" and select a network, then set its type to "Host-only"
4. Configure the network:
   - Subnet IP: 192.168.10.0
   - Subnet mask: 255.255.255.0
   - Uncheck "Connect a host virtual adapter to this network" (this prevents your host from being on the lab network)
   - Uncheck "Use local DHCP service to distribute IP addresses" (you will assign fixed IPs instead of automatic ones)
5. Click Apply and OK

This creates an isolated virtual switch that only your VMs can access. No traffic reaches the internet or your real network.

## Setting Up the Windows 11 Target Machine

The target machine is where your compiled loaders will run against Defender. This machine does NOT have Visual Studio or the .NET SDK installed. It only runs binaries. This is realistic because on a real engagement, the target machine is the client's computer and it does not have your development tools on it.

### Step 1: Download the Windows 11 ISO

Go to Microsoft's website and download the Windows 11 ISO. An ISO is a single file that contains an exact copy of an installation disc. Select Windows 11 (multi-edition), choose your language, and download the 64-bit version. The file is approximately 5-6 GB. You will use this same ISO for the dev box VM later.

### Step 2: Create the Virtual Machine

In VMware:
1. Click "Create a New Virtual Machine"
2. Select "Custom (advanced)". Do not use "Typical" because you need to control the hardware settings
3. Hardware compatibility: select the latest available version
4. Select "Installer disc image file (iso)" and browse to the Windows 11 ISO you downloaded
5. If VMware asks about Easy Install or product key, skip those screens
6. VM name: **Win11-Target**
7. Choose a storage location with at least 60 GB free space
8. Processors: 2 processors, 2 cores each (4 total cores). Windows 11 needs at least 2 cores. If your host has 8+ cores, you can give the VM more.
9. Memory: **8192 MB (8 GB)** if your host has 24+ GB RAM. Minimum is 4096 MB (4 GB), but 8 GB gives smoother performance. Windows 11 needs more RAM because Defender's real-time scanning and cloud analysis run constantly in the background.
10. Network: Select "Use host-only networking" and make sure it points to the host-only network you created (VMnet1 or whichever network has the 192.168.10.0 subnet)
11. SCSI controller: LSI Logic SAS (default)
12. Disk type: NVMe (faster) or SCSI (default)
13. Create a new virtual disk, 60 GB, store as single file
14. Click Finish

Before powering on, edit the VM settings:
1. Go to VM > Settings
2. Under Options > Advanced, make sure "Firmware type" is set to UEFI (Windows 11 requires UEFI, not legacy BIOS)
3. Under Hardware > Add, add a "Trusted Platform Module" (TPM) if VMware prompts you. Windows 11 requires TPM 2.0. A TPM is a security chip that stores encryption keys. VMware can simulate this chip in software.

### Step 3: Install Windows 11

Power on the VM. The Windows 11 installer starts:

1. Select your language, time format, and keyboard layout. Click Next.
2. Click "Install now"
3. "Activate Windows" screen: click "I don't have a product key". Windows 11 works without a key for testing purposes. It will show a watermark but all features work.
4. Select **Windows 11 Pro**. Not Home. Pro has features (like Remote Desktop and Group Policy Editor) that matter for security testing.
5. Accept the license terms
6. Choose "Custom: Install Windows only (advanced)"
7. Select the 60 GB unallocated drive and click Next
8. Wait 15-30 minutes for installation

During the out-of-box experience (OOBE), which is the first-time setup wizard that runs after Windows installs:
1. Select your country/region
2. Select your keyboard layout
3. When asked to connect to a network: **choose "I don't have internet"** and then "Continue with limited setup". This is critical because it lets you create a local account instead of a Microsoft account. A local account is simpler for lab purposes.
4. Enter the name: **kimjongun**
5. Set a password you will remember (you will need it for SMB transfers and logins)
6. Set the security questions (required by Windows)
7. On the privacy settings screens, turn everything off (location, diagnostics, inking, advertising). These are not relevant for the lab and reducing them lowers background network noise.

### Step 4: Install VMware Tools

VMware Tools is a set of drivers and utilities that improves the VM experience: better display resolution, shared clipboard, drag-and-drop file support, and better performance.

1. In VMware's menu bar, click VM > Install VMware Tools
2. This mounts a virtual DVD in the VM
3. Open File Explorer, navigate to the DVD drive (usually D:)
4. Run setup64.exe
5. Follow the installer with default settings
6. Restart the VM when prompted

After restart, you should be able to resize the VM window and the display resolution adjusts automatically. The mouse should also move smoothly between host and guest without pressing Ctrl+Alt.

### Step 5: Update Windows Fully

This step is important. You want the latest Defender signature database and the latest Windows security features.

1. Open Settings > Windows Update
2. Click "Check for updates"
3. Install all available updates
4. Restart when prompted
5. Check for updates again after restarting
6. Repeat until "You're up to date" shows with no pending updates

This process may take 30-60 minutes depending on how many updates are available. Some updates require multiple restarts. Be patient and keep checking until Windows says it is fully current.

### Step 6: Verify Defender Configuration

Open Windows Security (click the shield icon in the system tray at the bottom-right of your screen, or search for "Windows Security" in the Start menu):

**Virus & threat protection:**
- Real-time protection: ON
- Cloud-delivered protection: ON
- Automatic sample submission: ON
- Tamper protection: ON

Click "Virus & threat protection updates" and then "Check for updates" to get the latest Defender signature database.

**Firewall & network protection:**
- Firewall should be ON for all profiles. Do NOT disable it. Later, you may need to allow specific rules for ping or specific ports, but the firewall stays active.

**App & browser control:**
- Smart App Control: this may be set to "Evaluation" on a fresh install. Leave it as-is.
- SmartScreen: ON

**Device security:**
- Core isolation > Memory integrity: this may or may not be on depending on your CPU. Leave it at its default.

**Do not change any of these settings.** The entire point is testing against production Defender. Take a note of all the settings so you can verify they have not changed during testing.

### Step 7: Set a Static IP Address

The target machine needs a fixed IP address so Kali and the dev box always know where to find it.

1. Open Settings > Network & Internet > Ethernet
2. Click the network adapter (it should be the VMware host-only adapter)
3. Click Edit next to "IP assignment"
4. Change from "Automatic (DHCP)" to "Manual"
5. Toggle on IPv4
6. Enter:
   - IP address: **192.168.10.100**
   - Subnet prefix length: **24** (this is the same as subnet mask 255.255.255.0)
   - Gateway: leave blank
   - Preferred DNS: leave blank
7. Click Save

To verify, open Command Prompt and run:

```
ipconfig
```

You should see the Ethernet adapter with IP 192.168.10.100 and subnet mask 255.255.255.0.

### Step 8: Take a Snapshot

Take a snapshot of the target VM in its clean state.

1. In VMware, go to VM > Snapshot > Take Snapshot
2. Name it: "Clean - Lab Ready"
3. Add a description: "Windows 11 Pro, fully updated, Defender active, no dev tools, IP 192.168.10.100"
4. Click Take Snapshot

If anything goes wrong later (a loader corrupts the system, you accidentally change a Defender setting, etc.), you can restore this snapshot and be back to a known-good state in seconds.

**Important:** Do NOT install Visual Studio or the .NET SDK on this machine. The target machine only runs compiled binaries. All compilation happens on the dev box.

## Setting Up the Windows 11 Dev Box

The dev box is your malware development machine. This is where Visual Studio 2022 and the .NET SDK are installed. You compile all loaders here, then transfer only the compiled .exe files and encrypted shellcode to the target machine.

### Step 1: Create the Virtual Machine

You will use the same Windows 11 ISO you downloaded earlier.

In VMware:
1. Click "Create a New Virtual Machine"
2. Select "Custom (advanced)"
3. Select "Installer disc image file (iso)" and browse to the same Windows 11 ISO
4. VM name: **Win11-DevBox**
5. Choose a storage location with at least 60 GB free space
6. Processors: 2 processors, 2 cores each (4 total cores)
7. Memory: **8192 MB (8 GB)** if your host has 24+ GB RAM. You can use 4096 MB (4 GB) if RAM is tight, since Defender will be disabled on this machine and Visual Studio does not need 8 GB.
8. Network: **Use host-only networking** (the same host-only network, 192.168.10.0 subnet)
9. Disk: 60 GB, store as single file
10. Click Finish

Before powering on, edit VM settings and set UEFI firmware and add a TPM, same as you did for the target machine.

### Step 2: Install Windows 11

Follow the same Windows 11 installation steps as the target machine, with one difference:

During the OOBE (first-time setup):
4. Enter the name: **ammulu** (not kimjongun, that is the target machine)
5. Set a password you will remember

Everything else is the same: local account, privacy settings off.

### Step 3: Install VMware Tools

Same process as the target machine. Install VMware Tools, restart.

### Step 4: Install Visual Studio 2022 Community

This is where the development tools go. Not on the target.

1. Open Edge browser in the dev box VM
2. Temporarily add a NAT network adapter in VMware (VM > Settings > Add > Network Adapter > NAT) for internet access
3. Go to visualstudio.microsoft.com
4. Download Visual Studio 2022 Community
5. Run the installer
6. On the Workloads screen, check:
   - **.NET desktop development** (this installs the C# compiler, .NET SDK, and development tools for building console applications)
7. Click Install. Wait for the 5-8 GB download and installation to complete.
8. Launch Visual Studio once to complete initial setup (sign in or skip, choose a theme)
9. Close Visual Studio after initial setup

After Visual Studio is installed, remove the NAT network adapter:
1. Go to VM > Settings
2. Select the NAT network adapter you added
3. Click Remove
4. Click OK

The dev box is now back to host-only networking.

### Step 5: Verify the .NET SDK

Open a Command Prompt or PowerShell on the dev box and run:

```
dotnet --version
```

You should see version 8.0.x or later. If `dotnet` is not recognized, go back to Visual Studio Installer and verify the .NET desktop development workload is installed.

Also verify the C# compiler:

```
dotnet --list-sdks
```

This should show at least one SDK version installed.

### Step 6: Set a Static IP Address

1. Open Settings > Network & Internet > Ethernet
2. Click the network adapter (VMware host-only adapter)
3. Click Edit next to "IP assignment"
4. Change from "Automatic (DHCP)" to "Manual"
5. Toggle on IPv4
6. Enter:
   - IP address: **192.168.10.150**
   - Subnet prefix length: **24**
   - Gateway: leave blank
   - Preferred DNS: leave blank
7. Click Save

Verify with:

```
ipconfig
```

You should see IP 192.168.10.150 and subnet mask 255.255.255.0.

### Step 7: Disable Windows Defender

The dev box compiles malware. If Defender is active here, it quarantines your compiled .exe files before you can transfer them to the target. Defender testing only happens on the target machine (kimjongun, 192.168.10.100), never on the dev box. This is realistic because in a real red team engagement, your development machine does not run the same security controls as the client's machines.

To disable Defender on the dev box:

1. Open **Windows Security** (click the shield icon in the taskbar or search for "Windows Security")
2. Click **Virus & threat protection**
3. Under "Virus & threat protection settings", click **Manage settings**
4. Turn OFF all of these:
   - **Real-time protection** - OFF
   - **Cloud-delivered protection** - OFF
   - **Automatic sample submission** - OFF
   - **Tamper protection** - OFF (turn this off first if the other toggles keep turning back on)

Windows will show a warning that your device is vulnerable. That is expected. This machine is for compiling, not for testing.

**Important:** Windows may turn Real-time protection back on after a restart. If that happens, disable it again. For a permanent solution, you can disable Defender through Group Policy:

1. Press `Win + R`, type `gpedit.msc`, press Enter
2. Navigate to: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus
3. Double-click "Turn off Microsoft Defender Antivirus"
4. Select **Enabled**, click OK
5. Restart the VM

After restarting, verify Defender is off by opening Windows Security. It should show "Threat service has stopped. Restart it now." Do not restart it.

### Step 8: Take a Snapshot

1. VM > Snapshot > Take Snapshot
2. Name: "Clean - Lab Ready"
3. Description: "Windows 11 Pro, VS2022 installed, .NET SDK working, Defender disabled, IP 192.168.10.150, username ammulu"
4. Click Take Snapshot

## Setting Up the Kali Linux VM (Attacker Machine)

### Step 1: Download Kali Linux

Go to kali.org/get-kali and download the latest Kali Linux installer ISO (64-bit). The file is approximately 3-4 GB.

### Step 2: Create the Virtual Machine

In VMware:
1. Click "Create a New Virtual Machine"
2. Select "Custom (advanced)"
3. Select "Installer disc image file (iso)" and browse to the Kali ISO
4. VM name: **Kali-Attacker**
5. Processors: 2 processors, 1-2 cores each
6. Memory: **4096 MB (4 GB)**. Kali is lighter than Windows and 4 GB is enough.
7. Network: **Use host-only networking** (the same host-only network as the target and dev box, 192.168.10.0 subnet)
8. Disk: 40 GB, store as single file
9. Click Finish

### Step 3: Install Kali Linux

Power on the VM:
1. Select "Graphical install" from the boot menu
2. Choose your language and region
3. Hostname: **kali**
4. Domain name: leave blank
5. Full name: **kali**
6. Username: **kali**
7. Set a password
8. Partitioning: "Guided - use entire disk", select the 40 GB disk, "All files in one partition", confirm and write changes
9. Software selection: keep the default desktop environment (Xfce) and default tools selected
10. Install GRUB bootloader to the primary drive
11. Complete installation and restart

### Step 4: Set a Static IP Address

After booting into Kali and logging in, open a terminal.

First, find out what your network interface is called. A network interface is a connection point for networking. Each network adapter (real or virtual) gets its own interface name:

```bash
ip link show
```

Look for an interface that is NOT "lo" (lo stands for loopback, which is a special interface the computer uses to talk to itself). It will be something like `eth0`, `ens33`, or `ens160`. Note this name.

Now configure the static IP. Edit the network interfaces file:

```bash
sudo nano /etc/network/interfaces
```

Add these lines (replace `eth0` with your actual interface name if it is different):

```
auto eth0
iface eth0 inet static
    address 192.168.10.200
    netmask 255.255.255.0
```

Save the file (Ctrl+X, then Y, then Enter) and restart networking:

```bash
sudo systemctl restart networking
```

Verify the IP:

```bash
ip addr show eth0
```

You should see `inet 192.168.10.200/24` in the output.

If your Kali uses NetworkManager instead of /etc/network/interfaces (which is the case on newer Kali builds with a desktop environment), use this method instead:

```bash
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.10.200/24
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con up "Wired connection 1"
```

The connection name might be different. Run `nmcli con show` to see the exact name.

### Step 5: Verify Required Tools

Kali comes with most of the tools you need pre-installed. Verify each one:

```bash
# msfvenom generates shellcode payloads
msfvenom --version

# python3 hosts files via HTTP server
python3 --version

# smbclient transfers files to/from Windows shares
smbclient --version
```

If any tool is missing:

```bash
sudo apt update
sudo apt install -y metasploit-framework python3 smbclient
```

### Step 6: Take a Snapshot

Just like the Windows VMs, snapshot Kali in its clean state:

1. VM > Snapshot > Take Snapshot
2. Name: "Clean - Lab Ready"
3. Description: "Kali Linux, tools verified, IP 192.168.10.200"

## Compilation and Execution

### Testing Network Connectivity

All three machines need to reach each other. From Kali, ping both Windows machines:

```bash
ping -c 4 192.168.10.100
ping -c 4 192.168.10.150
```

You should see 4 replies from each. If you get "Destination Host Unreachable" or 100% packet loss:

1. Verify all three VMs are on the same host-only network (check VM Settings > Network Adapter on each VM)
2. Verify all static IPs are set correctly (`ip addr show` on Kali, `ipconfig` on both Windows machines)
3. On each Windows machine, check if the firewall is blocking ICMP (ping uses a protocol called ICMP). Open Windows Defender Firewall > Advanced Settings > Inbound Rules > find "File and Printer Sharing (Echo Request - ICMPv4-In)" > right-click > Enable Rule. This allows ping without disabling the firewall.

From the dev box (ammulu, 192.168.10.150), ping the target and Kali:

```
ping 192.168.10.100
ping 192.168.10.200
```

From the target (kimjongun, 192.168.10.100), ping the dev box and Kali:

```
ping 192.168.10.150
ping 192.168.10.200
```

All pings returning replies confirms full connectivity between all three machines.

### Testing File Transfer Method 1: Python HTTP Server

This is the primary method you will use to transfer shellcode from Kali to the dev box, and to transfer compiled loaders from the dev box to the target.

On Kali, create a test file and start a web server:

```bash
echo "file transfer test from kali" > /tmp/transfer_test.txt
cd /tmp
python3 -m http.server 8080
```

The terminal shows `Serving HTTP on 0.0.0.0 port 8080`. The server is running and will serve any file in /tmp to anyone who connects on port 8080.

On the dev box (ammulu), open PowerShell and download the file:

```powershell
Invoke-WebRequest -Uri "http://192.168.10.200:8080/transfer_test.txt" -OutFile "C:\Users\ammulu\Desktop\transfer_test.txt"
```

Then verify the file:

```powershell
Get-Content "C:\Users\ammulu\Desktop\transfer_test.txt"
```

You should see "file transfer test from kali". If this works, HTTP transfer from Kali to the dev box is ready.

Now test the same transfer to the target machine. On the target (kimjongun), open PowerShell:

```powershell
Invoke-WebRequest -Uri "http://192.168.10.200:8080/transfer_test.txt" -OutFile "C:\Users\kimjongun\Desktop\transfer_test.txt"
Get-Content "C:\Users\kimjongun\Desktop\transfer_test.txt"
```

On Kali, stop the Python server with Ctrl+C.

You also need to transfer files from the dev box to the target. On the dev box (ammulu), start a Python HTTP server. First, install Python on the dev box by temporarily adding a NAT adapter (same as you did for Visual Studio), downloading Python from python.org, installing it with "Add to PATH" checked, then removing the NAT adapter. Then:

```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

On the target (kimjongun), download a test file:

```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/transfer_test.txt" -OutFile "C:\Users\kimjongun\Desktop\transfer_from_devbox.txt"
```

This transfer path (dev box to target) is the most important one in the curriculum. Your workflow will be: generate shellcode on Kali, transfer it to the dev box, compile the loader on the dev box, then transfer the compiled .exe and any encrypted shellcode files from the dev box to the target. The target only runs things, it never compiles.

### Testing File Transfer Method 2: SMB Share

SMB is useful when you need bidirectional file transfer, especially when pulling files from Windows to Kali for analysis.

Set up an SMB share on the target machine (kimjongun, 192.168.10.100):
1. Create a folder: `C:\Share`
2. Right-click the folder > Properties > Sharing tab > Share
3. In the sharing dialog, type "Everyone" in the name field and click Add
4. Set the permission level to "Read/Write"
5. Click Share, then Done

On Kali, connect to the target's share:

```bash
smbclient //192.168.10.100/Share -U kimjongun
```

Enter the Windows user's password when prompted. You will see an `smb: \>` prompt. Test by uploading a file:

```
smb: \> put /tmp/transfer_test.txt
smb: \> ls
smb: \> exit
```

On the target, check C:\Share and you should see transfer_test.txt.

You can also set up an SMB share on the dev box (ammulu, 192.168.10.150) the same way if you want bidirectional SMB access between all three machines. Create `C:\Share` on the dev box and share it the same way.

### Verifying the Build Toolchain

On the dev box (ammulu, 192.168.10.150), open Command Prompt and run:

```
mkdir C:\Users\ammulu\Desktop\TestProject
cd C:\Users\ammulu\Desktop\TestProject
dotnet new console -n BuildTest
cd BuildTest
dotnet run
```

You should see "Hello, World!" printed. This confirms the .NET SDK compiles and runs C# code correctly on the dev box.

Clean up:

```
cd C:\Users\ammulu\Desktop
rmdir /s /q TestProject
```

Do NOT run this on the target machine (kimjongun). The target machine does not have the .NET SDK and should not have it. The target only runs compiled .exe files.

## Confirming Success

Your lab is fully set up when every item on this list is verified:

**Target Machine (kimjongun, 192.168.10.100):**
- [ ] Windows 11 Pro installed and fully updated
- [ ] Static IP set to 192.168.10.100
- [ ] Defender real-time protection: ON
- [ ] Defender cloud-delivered protection: ON
- [ ] Defender automatic sample submission: ON
- [ ] Defender tamper protection: ON
- [ ] Defender signature database is current (check for updates in Windows Security)
- [ ] No Visual Studio installed (this is the target, not the dev box)
- [ ] No .NET SDK installed
- [ ] Snapshot taken ("Clean - Lab Ready")

**Dev Box (ammulu, 192.168.10.150):**
- [ ] Windows 11 Pro installed
- [ ] Static IP set to 192.168.10.150
- [ ] Defender DISABLED (real-time protection OFF, or disabled via Group Policy)
- [ ] Visual Studio 2022 Community installed with .NET desktop development workload
- [ ] `dotnet --version` returns 6.0 or later
- [ ] `dotnet new console` and `dotnet run` produces "Hello, World!"
- [ ] Python installed for hosting HTTP server
- [ ] Snapshot taken ("Clean - Lab Ready")

**Kali Linux VM (kali, 192.168.10.200):**
- [ ] Kali Linux installed with default tools
- [ ] Static IP set to 192.168.10.200
- [ ] `msfvenom --version` works
- [ ] `python3 --version` works
- [ ] `smbclient --version` works
- [ ] Snapshot taken ("Clean - Lab Ready")

**Network and Transfers:**
- [ ] Kali can ping target (192.168.10.100) and dev box (192.168.10.150)
- [ ] Target can ping dev box (192.168.10.150) and Kali (192.168.10.200)
- [ ] Dev box can ping target (192.168.10.100) and Kali (192.168.10.200)
- [ ] Python HTTP server file transfer works (Kali to dev box)
- [ ] Python HTTP server file transfer works (dev box to target)
- [ ] SMB file transfer works (Kali to target)

## What Was Gained

You now have a complete, isolated lab that mirrors a real red team engagement setup:

- A Windows 11 dev box (ammulu, 192.168.10.150) with Visual Studio 2022 and the .NET SDK. This is where you compile all loaders. On a real engagement, this is your operator workstation where you build your tools before deploying them.
- A Windows 11 target (kimjongun, 192.168.10.100) with production Defender settings, exactly what you would encounter on a real client machine. The Defender configuration matches what most organizations run because they use the default settings. This machine only runs compiled binaries, just like a real target.
- A Kali attacker machine (kali, 192.168.10.200) with the tools needed to generate shellcode payloads (msfvenom), host files for transfer (python3 HTTP server), and interact with Windows file shares (smbclient).
- An isolated network where you can test aggressive techniques without affecting your real network or triggering alerts on systems outside the lab.
- Snapshots of all three VMs in their clean state so you can reset to a known-good configuration at any time.

The file transfer setup means you can move files between all three machines quickly. Throughout the curriculum, the workflow is: generate shellcode on Kali, transfer it to the dev box, compile the loader on the dev box, transfer the compiled .exe and any encrypted shellcode to the target, run the loader on the target, and observe whether Defender catches it. This three-machine workflow is realistic. On a real engagement, you never compile malware on the target machine. You build on your own machine and deliver only the final binary.

## Common Threats and Variations

### Variation 1: Using VirtualBox Instead of VMware

VirtualBox is free and works as a hypervisor, but it has weaker TPM emulation and less reliable host-only networking. If you use VirtualBox:
- Create a "Host-only Network" in VirtualBox (File > Host Network Manager)
- Set the network to 192.168.10.0/24 with no DHCP
- When creating VMs, attach a "Host-only Adapter" pointing to that network
- For Windows 11, you may need to modify the registry during installation to bypass TPM and Secure Boot requirements (search for "VirtualBox Windows 11 registry bypass" for current instructions)

Everything else in the curriculum works the same regardless of hypervisor.

### Variation 2: Kali in WSL Instead of a Separate VM

Windows Subsystem for Linux (WSL) can run Kali on your host machine. WSL is a feature that lets you run Linux programs inside Windows. The advantage is lower resource usage (no separate VM). The disadvantages:
- WSL shares the host's network, so it is not isolated. Your test traffic goes through your real network adapter.
- WSL has limited access to raw sockets and some network features that Metasploit needs.
- The separation between attacker and target is blurred because both run on the same machine.

For learning, a separate Kali VM is better because it forces you to work across machines, which is how real engagements work.

### Variation 3: Using Physical Machines

If you have two physical computers and an isolated switch (no uplink to the internet), you can use physical hardware instead of VMs. The advantage is better performance. The disadvantages:
- No snapshots. If something goes wrong, you reinstall from scratch.
- You need a dedicated Windows 11 machine that you are willing to format and rebuild.
- Physical machines are harder to reset between tests.

For this curriculum, VMs are recommended because snapshots let you quickly restore a clean state between loader tests.

## Detection and Defense (Blue Team Perspective)

This document covers lab setup, not attack techniques, so there are no attack-specific defenses to discuss. However, there are operational security practices that matter:

**Keep your lab network isolated.** Verify your VM network settings before every testing session. If a VM accidentally gets a bridged network adapter (which connects to your real network), your shellcode could make connections to real machines. Check VM Settings > Network Adapter before starting any testing.

**Snapshot before testing.** Take a snapshot before running each new loader. If a loader behaves unexpectedly (crashes the VM, corrupts system files, or triggers Defender in a way that changes its configuration), you can restore the snapshot and start over.

**Update Defender before testing.** Check for Defender signature database updates at the start of each testing session. The signatures change frequently, and you want your lab to reflect current detection capabilities. A loader that bypasses old signatures but gets caught by current ones gives you a false sense of security.

**Monitor Defender's quarantine.** Open Windows Security > Virus & threat protection > Protection history after each test. This shows what Defender caught, when it caught it, and which detection method was used (file scanning, behavior, cloud, etc.). This information tells you which Defender layer your loader failed to bypass, which directly tells you what you need to fix.

## What Comes Next

Start Document 02 (lab/materials/02_c_sharp_basics.md). It teaches C# programming from zero using security-focused examples. Instead of writing programs that calculate interest rates or sort shopping lists, you will learn C# by writing programs that manipulate bytes, convert data between formats, and work with the operating system. By the end of Document 02, you will understand enough C# to read and write every loader in this curriculum.
