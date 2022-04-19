---
title: "Emotet Loader Technical Analysis"
date: 2022-04-19 18:30:42 -0000
categories: Malware Analysis
---

# Executive Summary
Over the past few years, Emotet (also known as Geodo/Heodo) has become one of the most prolific and active botnets. Despite a takedown attempt, Emotet managed to return and co-operate with other malware operators.

Emotet follows a modular framework style with a variety of modules, which perform different tasks. Even though Emotet has its own modules, the main objective has changed to spreading and propagating third-party malware families (e.g. Qakbot, TheTrick/Trickbot). The following article presents the analysis findings of an Emotet loader sample, which was found in mid-February of 2022. The analysis solely focuses on the loader’s binary and does not aim to provide any further insights into the Emotet ecosystem. Furthermore, It should be noted that future code changes should be expected (e.g. changes to the network commands).

In summary, the following key features were identified:

* Emotet dynamically loads any required Windows API function. Similarly, the binary strings are decrypted at runtime.
* As in the last version, before the takedown attempt, Emotet uses a control-flow flattening technique (similar to the range loops of O-LLVM but not identical). The method appears to have slightly changed but the main concept remains the same.
* Emotet supports a set of network commands. The majority of them aim to load/execute additional code/files.

# Technical Analysis

The following subsections focus on the analysis of the Emotet loader.

## Strings/Configuration Encryption

Emotet keeps its strings in an encrypted format and decrypts any required strings at runtime. In total, Emotet uses three functions to decrypt different sets of strings but the decryption method remains the same in all of them. The decryption routine can be easily replicated in an IDA-Python script in order to statically decrypt the strings - this is available on GitHub [1].

Similarly, Emotet has an encrypted, embedded configuration (IP:Port format). The decryption routine remains the same as with any other encrypted string.

## Dynamic Windows API Functions

In order to make static analysis more-time consuming, Emotet loads any necessary API functions at runtime by hashing, with a custom algorithm, each API function name and then comparing it with the associate hash of the API function that it needs to load.

Before attempting to solve this issue, I noticed the following:

* Each Windows API has its own method/function in the binary file.
* During the initialisation phase, Emotet decrypts certain Windows library names and loads them.

With the above information, I followed the below steps to map each Windows API function name to IDA:

* Identified the function, which loads each requested Windows API function.
* Identified the DLLs that Emotet will load at run-time (from the decrypted strings) in order to properly load their exported API functions.
* Wrote an x64dbg script that loads the required DLL files, finds all references to the function that does the API loading and executes the start address of each referenced function. The result was the Windows API function name for each function.
* Considering that each API function was its own function, I mapped each resolved API function name to its own function with an IDAPython script.

After following the above steps, the majority of the functions are renamed and only the core features are left for analysis. The x64dbg script is available on GitHub [2].

## Calling Convention and Stack Pointer

During the analysis, I encountered several issues with the calling convention of the functions. IDA was identifying some functions’ calling convention either as *thiscall* or *usercall* (IDA’s way to define a custom convention). It is not clear if this an intentional attempt from the author(s) to make the analysis harder. Unfortunately, the only way to overcome this issue was to manually check each function.

Furthermore, due to the dynamic loading of the Windows functions, the stack pointer had to be fixed in order to have a proper decompiled output.

## Control Flow Flattening

One of the core anti-analysis methods that Emotet has introduced is the control-flow flattening technique. In summary, by using this method, Emotet obfuscates its control flow and makes it harder to follow the execution flow of each function. It should be noted that this is not a new addition to Emotet since it has been used even before the takedown attempt.

To overcome this issue, I used a publicly available IDA plugin [3]. Even though it is not a perfect solution, I prefered this method because it operates in IDA’s microcode language and avoids any binary modifications.

*Note: There are better solutions to encounter Emotet’s flattening method. One of them is to use the miasm framework [4].*

## Initialisation Phase

Upon first execution, the loader checks the number of command line parameters. If there are more than 3 then it decodes (base64) the 3rd parameter and extracts the following information:

* Randomly generated filepath of Emotet.
* Object handle. The loader waits for this handle to signal before spawning a new instance of itself with *regsvr32.exe*.

Then, it copies the loader’s binary file into the Windows AppData folder under a different (random) filename and executes it from that location (the copied binary has the *Zone.Identifier* removed). This functionality is most likely being used when the loader is updated (Network command ID 1).

On the other hand, if the number of command line parameters is equal to or less than 3 (or if the parsing of the 3rd parameter is not successful), it proceeds to the execution of other code checks (e.g, loader’s modified timestamp check).

It is worth noting that Emotet uses a custom checksum algorithm to confirm if it is running under the process name *services.exe*. The checksum algorithm is the following:

```python
for image_name in processes:
	image_name = image_name.encode()
	output = 0
	for character in image_name:
		if character >=0x41 and character<=0x5A:
			character += 0x20
		output = ((output << 16) + (output << 6) + (character&0xffffffff) - (output&0xffffffff))&0xffffffff
```

The above algorithm is also used when Emotet loads a Windows API.

## Monitoring Thread

The loader creates a thread, which monitors for any filename changes of the loader. Where there is a change, the loader checks if an updated version of itself was downloaded from the command-and-control server and executes it.

## Persistence

Emotet uses two methods to add persistence to the compromised host. These are:

* Creation of a new service. The service name is the Emotet’s loader filename and the command line is: *C:\WINDOWS\SysWOW64\regsvr32.exe /s Emotet_Loader_Filepath*
* Creates a new key under the Run registry key, *SOFTWARE\Microsoft\Windows\CurrentVersion\Run*. The key’s name is the current filename and the value of the key is: *C:\WINDOWS\SysWOW64\regsvr32.exe /s Emotet_Loader_Filepath*

It is worth noting that the loader compares its binary modified timestamp with the current timestamp of the compromised host. If there is a time difference of 7 days or more then it removes the old persistence values, renames the current loader binary and creates a new service. The timestamp of the new file is derived from the current time of the compromised host.

## Network Communication

Probably the only interesting feature of the loader (from a technical point of view at least) is the network communication between the loader and its command-and-control servers. The main goal of the loader is to constantly connect to one of its command-and-control servers and request/receive commands.

Contrary to previous loader versions, the current Emotet loader does not use any compression for its network data. Instead, it encrypts them using a derived AES key and appends the encrypted output to the HTTP request.

Furthermore, the loader supports both GET and POST requests. The loader uses GET requests when the data’s size is less than 1024 bytes. Otherwise, it uses POST requests.

The encryption procedure of the network data is as follows:

* Collects information about the compromised host and creates the below structure:

```c
struct Network_Registration_Request
{
 DWORD Bot_ID_Length;
 BYTE Bot_ID[Bot_ID_Length];
 DWORD Loader_Filename_Hash; //Generated with the algorithm described in section ‘Initialisation Phase’.
 DWORD Loader_Version_Date;
 DWORD Loader_Builder_Number; // E.g. set to 10000
 DWORD OS_Info;
 DWORD Session_ID;
 DWORD Module_Data;
};
```

* Hash the above data and create a new structure, which is the following:

```c
struct Hashed_Data
{
 DWORD Module_ID;
 DWORD Hash_Size;
 BYTE Hash[Hash_Size];
 DWORD Network_Registration_Request_Size;
 BYTE Network_Registration_Request[Network_Registration_Request_Size];
};
```

* Encrypt the above structure (Hashed_Data) using the derived AES key. The final format of the network data, which is sent over to the command-and-control server is:

```c
struct Final_C2_Data_Format
{
 BYTE Generated_Public_ECDH_Key[0x40];
 BYTE Encrypted_Data[]; // hashed_Data structure
 BYTE Random_Generated_Bytes[]; // The size of them is random. If any 00s then replace it with 0xC3. Lastly, it picks a random byte from these bytes and replaces it with 0x00.
};
```

* Append the data to a HTTP request. For example:


```c
Headers: Content-Type: multipart/form-data; boundary=--------LBKTtCPwQp
----------LBKTtCPwQp

HTTP Body Content: Content-Disposition: form-data; name="pwh"; filename="QchlC"
Content-Type: application/octet-stream
Encrypted_Data
----------LBKTtCPwQp–-
```
The request’s URI along with the values *LBKTtCPwQp*, *QchlC* and *pwd* are randomly generated.

If the command-and-control server parses the loader’s request without any issues, it replies with a command that the loader should execute. It should be noted that the received data is decrypted (*BCryptDecrypt*) and verified (ECDSA).

Table 1 summarises the identified network commands.

| Command ID | Description | 
| --- | --- | 
| 1 | Updates the loader. The loader is executed by *regsvr32* along with the appropriate parameters.|
| 2 | Downloads and executes a DLL file in memory. The downloaded DLL file is most likely a module of Emotet.|
| 3 | Downloads and executes an EXE file. The file is written into disk.|
| 4 | Downloads and executes an EXE file under the current active console session. The file is written to disk.|
| 5 | Downloads and executes a DLL file in memory. The downloaded DLL must have an export with name *DllRegisterServer*. The downloaded DLL file is most likely a module of Emotet.|
| 6 | Downloads and executes a DLL file with *regsvr32.exe*. The file is written into disk.|

*Table 1: Network Commands*

# References

1.  https://github.com/nikpx/Various_Scripts/blob/main/Emotet/Emotet_IDA_Strings_Decryption.py
2.  https://github.com/nikpx/Various_Scripts/blob/main/Emotet/Resolve_APIs_X64dbg_Script
3.  https://github.com/ElvisBlue/emotet-deobfuscator
4.  https://github.com/ulexec/EmotetCFU
