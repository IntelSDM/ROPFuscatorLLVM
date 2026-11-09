# Ropfuscator
Built for LLVM 19.1 - Windows x64 <br> <br>

Environment Emulation is becoming more and more popular, one of the key systems they rely on is checking fault RIPs. This allows them to see the variables you read/write to/ the functions you call. To circumvent your obfuscation. <br>
This is called fault analysis. The easiest way to break it is to simply indirectly invoke your memory interactions and function calls with ROP gadgets into other modules. <br>
Additionally, this forces AI to have to KEEP nearly all of these modules in its memory to scan for the gadgets. This FLOODS the AI's context, unlike other methods of drawing context, as you can have thousands of gadgets, they aren't all repeating and are of different usages. <br>
This means the AI can't optimise them, they need all the executable pages of all dlls the program can interact with in its context at all times to attack a ROP Fuscated binary. <br>

Unlike ROP for exploitation we can use calls to achieve what we want, we aren't hiding our callstack or stack interactions. We are hiding the actual fault's RIP. This creates CET compliance. <br>
Sadly since we are CET compliant, we aren't unwind compliant. As we directly invoke mid function instructions onto the callstack, so stackwalking from Anti Viruses and Anti Cheats will see you operating in violation of known unwind info. <br>

We effectively can Call, Read, Write memory while circumventing fault analysis, And destroy AI context performance. <br>

<img width="1083" height="532" alt="image" src="https://github.com/user-attachments/assets/421e1ab7-75d7-434c-aa16-16a205687579" /> <br>
<img width="1154" height="267" alt="image" src="https://github.com/user-attachments/assets/bed6a102-ce6f-470c-b526-ff4377659660" /> <br>
<img width="775" height="141" alt="image" src="https://github.com/user-attachments/assets/02a4e218-4053-439d-a9ca-3e46f03c3916" /> <br>
<img width="508" height="301" alt="image" src="https://github.com/user-attachments/assets/a86ffaa1-2ba2-4ffa-8e20-708a0654046a" /> <br>


## How to use
* First of all you need a build server that already grabs the users dll info. DLLGrabberUtility.h Is how you grab the info from the user, Call GrabIdentity on their end. 
* Then once we have the TimeDateStamp SizeOfImage DllName from the user, we can query the DLLs directly from Microsoft's download server; as seen in OfficialDLLDownloader.h.
* So you now have the dlls from your user from Microsoft's server, they are on disk, you then use the DLLExportGrabber.h on them, use them in the pass. 
* Each Windows build has a unique build. 
* Then cache the output, if the user has a repeat build with the same DLLs, you then give them the existing output, otherwise you build them a new one for their windows build

## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
