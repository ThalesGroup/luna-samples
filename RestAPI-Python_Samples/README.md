## PYTHON REST-API SAMPLES FOR LUNA NETWORK HSM
<BR>

>[!NOTE]
> These samples are for testing purposes only!
> The Luna REST API is intended for HSM-related management tasks only.

<br>

>[!CAUTION]
> Some of these samples demonstrate the execution of destructive tasks, such as deletion.
> Repeated failed login attempts beyond the permitted threshold may result in lockout or zeroisation.
> Please do not use these samples if you are unfamiliar with these management tasks.

<BR><BR>
| SAMPLE NAME | DESCRIPTION |
| --- | --- |
| client_list | displays a list of all registered clients |
| client_show | displays information about a client. |
| client_delete | deletes a registered client. |
| change_role_password | demonstrates how to change SO, PSO, CO, and CU password. |
| partition_list | lists all partitions in a Luna Network HSM |
| partition_create | demonstrates how to create a partition. |
| partition_delete | demonstrates how to delete a partition. |
| certificate_based_authentication | demonstrates certificate based authentication using Luna RestAPI. |
| user_create | demonstrates how to create a user. |
| user_delete | demonstrates how to delete a user. |
| user_list | displays a list of all users in a Luna Network HSM. |
| user_set_certificate | demonstrates how to set a certificate to a user. |


<BR><BR>
### How to execute these samples?

- Simply executing a sample without arguments will display the correct syntax.
```
	sampaul@thales:~/LunaHSM_Sample_Codes/RestAPI-Python_Samples$ ./client_list
	usage :-
	./client_list <HSM_IP_OR_HOST> <appliance_username>


	sampaul@thales:~/LunaHSM_Sample_Codes/RestAPI-Python_Samples$ ./partition_list
	usage :-
	./partition_list <HSM_IP_OR_HOST\> <appliance_username>
```


- The password input is not displayed (echoed).

- Prompts for confirmation such as, Yes/No, proceed, are case-sensitive (intentionally).

```

	sampaul@thales:~/LunaHSM_Sample_Codes/RestAPI-Python_Samples$ ./partition_create hsm1.<fqdn> spaul
	[spaul] Password :
	Connecting to Luna HSM : [ hsm1.<fqdn> ]


	Please enter the security officer password to proceed.
	Caution: Three failed SO login attempts will zeroize the Luna HSM.
	SO Login Attempts left :  3

	SECURITY OFFICER PASSWORD :
	SO Login successful.


	Partition name : thisisatest
	Partition version (0 or 1) : 0
	Partition 'thisisatest' created successfully.

	Would you like to create more partitions? Please type 'Yes' or 'No' : No
	Exiting...



	sampaul@thales:~/LunaHSM_Sample_Codes/RestAPI-Python_Samples$ ./partition_list 10.0.0.100 spaul
	[spaul] Password :
	Connecting to Luna HSM : [ 10.0.0.100 ]

	SERIAL          NAME            STATE           VERSION
	1682975235230   SP_SKS_SEHSM3   initialized     1
	1682975235231   thisisatest     zeroized        0
```
