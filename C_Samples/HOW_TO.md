# HOW TO guide for C_Samples
------------

### Compiling the code

**Unix / Linux** : There are three ways to compile the source file
- Manual compile <BR>
 `gcc Connect_and_Disconnect.c -o Connect_and_Disconnect -I/usr/safenet/lunaclient/samples/include/ -DOS_UNIX*`

- Using Makefile <BR>
  - `make` : Defaults to building all C files.<br>
  - `make all` : Builds all C files.<br>
  - `make clean` : Removes all executable binaries.<br>
  - `make list_samples` : Displays a list of all available samples.<br>
  - `make encryption` : Builds all encryption demonstration samples.<br>
  - `make signing` : Builds all signing demonstration samples.<br>
  - `make keygen` : Builds all samples demonstrating key generation.<br>
  - `make objmgmt` : Builds all samples to demonstrate object management.<br>
  - `make sfntExtension` : Builds all samples to demonstrate the usage of SFNTExtension.<br>
  - `make misc` : Build all other miscellaneous samples.<br>
  - `make help` : Displays all make options.<br>

- If you want to compile a specific C file, you can pass the filename (without the .c extension or the path) to make command. For example:<br>
  - `make CKM_AES_KEY_GEN_demo`<br>
  - `make C_CreateObject_demo`<br>
  - Use `make list_samples` to view the list of all available samples.<br>

**Windows**
- Manual compile using MINGW<br>
`gcc Connect_and_Disconnect.c -o Connect_and_Disconnect.exe -I"C:\Program Files\SafeNet\LunaClient\samples\p11sample\include" -DOS_WIN32`

- Manual compile using MSVC<br>
 `cl Connect_and_Disconnect.c /I"C:\Program Files\SafeNet\LunaClient\samples\p11sample\include" /D "OS_WIN32"`
<br>

------------

### Executing a compiled sample code.

Before running the executable binary, you must set the **P11_LIB** environment variable. **P11_LIB** should contain the absolute path to cryptoki library. See examples below -
<BR>

**Unix / Linux -**

`export P11_LIB=/usr/safenet/lunaclient/lib/libCryptoki2_64.so`
        
 `export P11_LIB=/usr/lib/libCryptoki2.so`
        
 `export P11_LIB=/usr/lib/libcklog2.so`
        
 `export P11_LIB=$ChrystokiConfigurationPath/lib/libCryptoki2_64.so`

**Windows -**

`set P11_LIB=C:\Program Files\SafeNet\LunaClient\cryptoki.dll`

`set P11_LIB=C:\Program Files\SafeNet\LunaClient\cklog2.dll`

`set P11_LIB=C:\Program Files\SafeNet\LunaClient\shim.dll`
<BR><BR>

**Running the executable file.**

Executing the compiled binary will display the syntax to use. See example below -

`sampaul@thales:~$ export P11_LIB=/usr/lib/libCryptoki2_64.so`<br><br>
`sampaul@thales:~$ ./Connect_and_Disconnect`<br>
`Usage :-`<br>
`./Connect_and_Disconnect <slot_number> <crypto_office_password>`<br><br>
`sampaul@thales:~$ ./Connect_and_Disconnect 0 userpin`<br>
`./Connect_and_Disconnect`<br>
`> P11 library loaded.`<br>
`--> /usr/lib/libCryptoki2_64.so`<br>
`> Connected to Luna.`<br>
`--> SLOT ID : 0.`<br>
`--> SESSION ID : 1.`<br>
`> Disconnected from Luna slot.`<br>
