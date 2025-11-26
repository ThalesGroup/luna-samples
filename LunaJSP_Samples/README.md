## SAMPLE CODES FOR Luna JSP (LunaProvider)

| **DIRECTORY** | **DESCRIPTION** | **NUMBER OF SAMPLES** |
| --- | --- | --- |
| luna_keystore | samples demonstrating how to use luna keystore. | 8 |
| misc | samples demonstrating miscellaneous tasks. | 5 |
| object_management | samples demonstrating how to manage different types of pkcs11 objects. | 16 |
| slot_management | samples demonstrating various slot management related operations. | 4 |
| crypto_operations | samples demonstrating various cryptographic operations using LunaProvider. | 19 |
| pqc | samples demonstrating the usage of various pqc algorithms. | 7 |
---------
<br>

### Guidelines for Compiling and Executing LunaJSP Sample Codes
- **Java Security Provider**: The correct method to compile and execute these codes depends on how LunaJSP is configured on your machine. These samples will first attempt to load LunaProvider from java.security. If LunaProvider is not found in java.security, the sample code will dynamically add it at runtime. Therefore, there is no need to configure LunaProvider statically in java.security to run these samples.
- **Luna JSP Libraries**: These samples require LunaJSP libraries to compile and execute. The two required files are LunaProvider.jar and libLunaAPI.so (Unix/Linux) or LunaAPI.dll (Windows).
- **ClassPath/Java Library Path**: If the JRE does not know where to find the two LunaJSP libraries, you need to use classpath and java.library.path to execute the code.
- **JDK/JRE**: I used OpenJDK 17.0.2 / 21.0.8 for testing all samples, although I am confident these samples will work with other supported JDKs (up to JDK 21).
- **Runtime Arguments**: These sample codes do not use hardcoded information such as usernames, passwords, or slot labels. You are required to provide this information as arguments when executing the samples.
-------
<br>

### <u>Compiling the code</u>
- **If JDK knows where to find Luna JSP files:**
	- Example 1:
	<pre>
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ javac LoginLogout.java
	</pre>

	- Example 2:
	<pre>
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ javac crypto_operations/EncryptUsing_AESCTRMode.java
	</pre>
	
- **Else, Using classpath:**
	- Example 1:
		<pre>sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ javac -cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar LoginLogout.java</pre>

	- Example 2:
		<pre>sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ javac -cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar crypto_operations/EncryptUsing_AESCTRMode.java</pre>

------
### <u>Executing the code.</u>
- **If JDK knows where to find Luna JSP files:**

	- Example 1:	
	<pre>
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ java LoginLogout
	[ LoginLogout ]
	Usage-
	java LoginLogout <crypto_officer_password>
	Example -
	java LoginLogout userpin
	
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ java LoginLogout userpin1
	LOGIN: SUCCESS
	LOGOUT: SUCCESS
	</pre>

	-	Example 2:
	<pre>
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ java -cp crypto_operations EncryptUsing_AESCTRMode
	[ EncryptUsing_AESCTRMode ]
	Usage-
	java EncryptUsing_AESCTRMode <slot_label> <crypto_officer_password>
	Example -
	java EncryptUsing_AESCTRMode myPartition userpin
	
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ java -cp crypto_operations EncryptUsing_AESCTRMode LAB userpin1
	Login : SUCCESS.
	LunaProvider found in java.security
	AES key generated.
	Plaintext encrypted.
	Ciphertext decrypted.
</pre>

- **Else, Using classpath and java.library.path:**

	- Example 1:
	<pre>
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ java -Djava.library.path=/usr/safenet/lunaclient/jsp/lib/ -cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar: LoginLogout userpin1
	LOGIN: SUCCESS
	LOGOUT: SUCCESS
	</pre>
	- Example 2:
	<pre>
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ java -Djava.library.path=/usr/safenet/lunaclient/jsp/lib/ -cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar:crypto_operations: EncryptUsing_AESCTRMode
	[ EncryptUsing_AESCTRMode ]
	Usage-
	java EncryptUsing_AESCTRMode <slot_label> <crypto_officer_password>
	Example -
	java EncryptUsing_AESCTRMode myPartition userpin
	
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ java -Djava.library.path=/usr/safenet/lunaclient/jsp/lib/ -cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar:crypto_operations: EncryptUsing_AESCTRMode LAB userpin1
	Login : SUCCESS.
	LunaProvider added to java.security
	AES key generated.
	Plaintext encrypted.
	Ciphertext decrypted.
	</pre>
	- Example 3: Java version 11 and above allows a user to execute Java code without compiling it first.
	<pre>
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ java -Djava.library.path=/usr/safenet/lunaclient/jsp/lib/ -cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar crypto_operations/EncryptUsing_AESCTRMode.java LAB userpin1
	Login : SUCCESS.
	LunaProvider added to java.security
	AES key generated.
	Plaintext encrypted.
	Ciphertext decrypted.
	</pre>

- **USE run.sh script (For Linux and JAVA 11 or newer.)**
	<pre>
	sampaul@thales:~/LunaHSM_Sample_Codes/LunaJSP_Samples$ ./run.sh crypto_operations/EncryptUsing_AESCTRMode.java LAB userpin1
	Login : SUCCESS.
	LunaProvider added to java.security
	AES key generated.
	Plaintext encrypted.
	Ciphertext decrypted.
	</pre>
