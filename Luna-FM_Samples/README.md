## SAMPLE CODES FOR Luna Functionality Module (FM)

Documentation: https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/FM_SDK/preface.htm
<br><br>

### DISCLAIMER

- Functionality Modules (FM) are custom-developed code for specific use-cases, that operates alongside firmware, within the secure confines of Luna HSM.
- It is assumed that you are already aware of what Functionality Modules can do, its limitation and risks associated with them.
- These samples require an FM-capable and FM-enabled Luna HSM. FM is supported by Luna Network HSM 7 and Luna PCIe 7 with firmware 7.4.0 or newer.
- These samples were written using Universal Client 10.3.0 and Luna Network HSM running firmware 7.7.1.
--------------------------------------
<br>

| **DIRECTORY** | **DESCRIPTION** | 
| --- | --- |
| Caesar | A basic sample to demonstrate how FM and host application works. |
---------------------------------------
<br>

### <u>Compiling the code (FM and HOST)</u>
- To build everyting: Use `make all`
- Or if you want to build either one of them, there's a makefile present inside both the FM and host directories.
<BR>

### <u>Generating keys for signing FM.</u>
- Before creating an FM file, you must generate a key pair. The private key will then be used for signing the bin file, producing the FM file.
- The procedure for generating signing keys and certificate are as follows:
	+ Generate signing keys using cmu.
	<pre>
		sampaul@jaguarkick:~$ cmu gen -labelprivate LunaFM_privKey -labelpublic LunaFM_pubKey -sign 1 -verify 1 -extractable 0 -modifiable 0 -keytype rsa -publicexponent 65537 -modulusbits 2048 -password $COPASS
		Certificate Management Utility (64-bit) v10.3.0-275. Copyright (c) 2020 SafeNet. All rights reserved.
		Select RSA Mechanism Type -
		[1] PKCS [2] FIPS 186-3 Only Primes [3] FIPS 186-3 Auxiliary Primes : 3
		...The key pair was successfully generated -> public handle(1126), private handle(1128)


		sampaul@jaguarkick:~$ cmu list -password $COPASS
		Certificate Management Utility (64-bit) v10.3.0-275. Copyright (c) 2020 SafeNet. All rights reserved.
		handle=1128     label=LunaFM_privKey
		handle=1126     label=LunaFM_pubKey
	</pre>
	+ Generate certificate.
	<pre>
		sampaul@jaguarkick:~$ openssl rand -hex 8
		023d673f6aaed561

		sampaul@jaguarkick:~$ cmu self -label JaguarKick -basicconstraints=ca:false -keyusage=digitalsignature,nonrepudiation -extendedkeyusage=codesigning -password $COPASS
		Certificate Management Utility (64-bit) v10.3.0-275. Copyright (c) 2020 SafeNet. All rights reserved.
		Enter certificate serial number : 023d673f6aaed561
		Enter Subject 2-letter Country Code (C) : CA
		Enter Subject State or Province Name (S) : BC
		Enter Subject Locality Name (L) :
		Enter Subject Organization Name (O) : Thales
		Enter Subject Organization Unit Name (OU) : Sales Engineering
		Enter Subject Common Name (CN) : JaguarKick
		Enter EMAIL Address (E) :
		Enter validity start date
		 Year   : 2025
		 Month  : 01
		 Day    : 01
		Enter validity end date
		 Year   : 2027
		 Month  : 12
		 Day    : 31
		Using "CKM_SHA256_RSA_PKCS" Mechanism
		...The certificate object was successfully created -> handle(1000)
	</pre>
	+ Export certificate to a file.
	<pre>
		sampaul@jaguarkick:~$ cmu export -out JaguarKick.cer -password $COPASS
	</pre>
<BR>
------------------

### <u>Making Functionality Module.</u>
- Executing make produces a bin file inside fm/bin directory, which is later used for making FM.
<pre>
	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar$ cd fm
	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar$ make
	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar$ ls bin-ppc/
	caesar.bin
</pre>
<br>
- Sign the output bin file to produce FM file.
<pre>
	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar$ vtl ver
	vtl (64-bit) v10.3.0-275. Copyright (c) 2020 SafeNet. All rights reserved.
	
	The following Luna SA Slots/Partitions were found:

	Slot    Serial #                Label
	====    ================        =====
	   0       1582163089435        SEHSM2-SP


	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar$ mkfm -f bin-ppc/caesar.bin -o caesar.fm -k SEHSM2-SP/LunaFM_privKey -p $COPASS
	Luna Functionality Module Signer Utility (64-bit) v10.3.0-275. Copyright (c) 2020 SafeNet. All rights reserved.
	mkfm: Processing ELF file bin-ppc/caesar.bin
	File successfully signed

	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar$ ls -l caesar.fm
	-rw-rw-r-- 1 sampaul sampaul 7593 Feb 21 16:06 caesar.fm
</pre>
<br>

- Upload the certificate and FM file to Luna HSM as the "admin" user; **FMs uploaded by other accounts cannot be loaded.**
<pre>
	sampaul@jaguarkick:~$ scp -O JaguarKick.cer admin@HSM-HOSTNAME:
	HSM-HOSTNAME's password:
	
	sampaul@jaguarkick:~$ scp -O caesar.fm admin@HSM-HOSTNAME:
	HSM-HOSTNAME's password:
</pre>
<br>

- Connect as admin to Lunashell (lunash) and log in as SO.
<pre>
	
	[HSM-HOSTNAME] lunash:>hsm login
	  Please enter the HSM Administrators' password:
	  > **************
	'hsm login' successful.
</pre>
<br>

- Load the signed FM file.
<pre>
	[HSM-HOSTNAME] lunash:>hsm fm load -fmFile caesar.fm -certFile JaguarKick.cer
	Importing FM on device 0
	Functionality Module download in progress, please wait...
	Functionality Module downloaded successfully.

</pre>
<br>

- HSM is required to be restarted to activate the newly loaded FM.
<pre>
	[HSM-HOSTNAME] lunash:>hsm fm status
	Getting status of the FM on all available devices
	Current Functionality Module Configuration for device 0:
	Serial # : -------
	Model    : Luna K7
	SMFS     : Activated

	Host FM apps will see this HSM as device 0.
	FM Label      : Caesar
	FM ID         : a000
	Version       : 1.00
	Manufacturer  : Thales
	Build Time    : Fri Feb 21 19:34:04 2025 - EST
	Fingerprint   : 79 37 42 92 D7 97 1D AB 0F DA
	ROM size      : 7310
	Status        : Loaded (reboot HSM to activate)
	Startup Status: N/A (FM not started)


	[HSM-HOSTNAME] lunash:>hsm restart
	WARNING !!  This command will restart the HSM card.
	If you are sure that you wish to proceed, then type 'proceed', otherwise type 'quit'
	> proceed
	Proceeding...
	Restarting HSM card in progress. Please wait...

</pre>
<br>

- After HSM restart, the newly loaded FM should appear with OK status.
<pre>
	[HSM-HOSTNAME] lunash:>hsm fm status
	Getting status of the FM on all available devices

	Current Functionality Module Configuration for device 0:
	Serial # : -------
	Model    : Luna K7
	SMFS     : Activated

	Host FM apps will see this HSM as device 0.

	FM Label      : Caesar
	FM ID         : a000
	Version       : 1.00
	Manufacturer  : Thales
	Build Time    : Fri Feb 21 19:34:04 2025 - EST
	Fingerprint   : 79 37 42 92 D7 97 1D AB 0F DA
	ROM size      : 7310
	Status        : Enabled
	Startup Status: OK
</pre>
----------------
<br>

### <u>Using FM Host Application</u>
<br>
- Build host application
<pre>
	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar/host$ make
	mkdir -p bin
	mkdir -p obj
	gcc -fPIC -x c -c -Wall -Werror -O2 -I/usr/safenet/lunaclient/samples/include -I/usr/safenet/lunafmsdk/include/fm/host -I/usr/safenet/lunafmsdk/include -I../include -DOS_LINUX -DOS_UNIX -D__EXTENSIONS__ -D_RWSTD_MULTI_THREAD -D_REENTRANT -D_THREAD_SAFE -DLUNA_LITTLE_ENDIAN -DUSE_PTHREADS -DLUNA_LP64_CORRECT -DDEBUG -D_USESSL -DDISABLE_CA_EXT  caesar_client.c -oobj/caesar_client.o
	g++ -obin/caesar_client  obj/caesar_client.o -L/usr/safenet/lunaclient/lib -lCryptoki2_64 -lethsm -lc -lpthread -ldl -lrt -Wl,-rpath=/usr/safenet/lunaclient/lib
</pre>
<br>
- Execute host application to ENCRYPT.
<pre>
	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar/host$ ./bin/caesar_client 0 -E hello
	FM Name is : Caesar.
	FM ID is : a000
	Adapter ID : 0
	Embedded Slot ID : 9.
	Received message : KHOOR.
</pre>
- Execute host application to DECRYPT.
<pre>
	sampaul@jaguarkick:~/LunaHSM_Sample_Codes/Luna-FM_Samples/caesar/host$ ./bin/caesar_client 0 -D KHOOR
	FM Name is : Caesar.
	FM ID is : a000
	Adapter ID : 0
	Embedded Slot ID : 9.
	Received message : HELLO.
</pre>
