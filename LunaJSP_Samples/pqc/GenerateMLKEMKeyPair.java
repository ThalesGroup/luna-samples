        /*********************************************************************************
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2025 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************

        OBJECTIVE :
	- This sample demonstrates how to generate ML-KEM keypair using LunaProvider.
	- This sample required Luna Client 10.9.1 to execute.
	- Keypair generated using this sample is ephemeral, i.e. a session keypair.

*/

import java.io.Console;
import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class GenerateMLKEMKeyPair {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair mlkem = null;
	private static final String PROVIDER = "LunaProvider";


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ GenerateMLKEMKeyPair ]\n");
		System.out.println("Usage-");
		System.out.println("java GenerateMLKEMKeyPair <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java GenerateMLKEMKeyPair myPartition userpin\n");
	}


        // Add LunaProvider to security provider list.
        private static void addLunaProvider() {
                if(Security.getProvider(PROVIDER)==null) {
                        Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
                        System.out.println("LunaProvider added to java.security");
                } else {
                        System.out.println("LunaProvider found in java.security");
                }
        }


	// generates mlkem keypair
	private static void generateKeyPair() throws Exception {
		Console con = System.console();
		int keyType; String mlkemParam = "";

		System.out.println("\nML-KEM 512 ......... 1");
		System.out.println("ML-KEM 768 ......... 2");
		System.out.println("ML-KEM 1024 ......... 3");
		System.out.print("Security Level : ");
		keyType = Integer.parseInt(con.readLine());

		if(keyType==1)
			mlkemParam = "ML-KEM-512";
		else if(keyType==2)
			mlkemParam = "ML-KEM-768";
		else if(keyType==3)
			mlkemParam = "ML-KEM-1024";
		else {
			System.out.println("Incorrect key type entered.");
			System.exit(1);
		}

		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(mlkemParam, PROVIDER);
		mlkem = keyPairGen.generateKeyPair();
		System.out.println("\nML-KEM keypair generated.");
	}


	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();

			if(slotManager.findSlotFromLabel(slotLabel)!=-1) { // checks if the slot number is correct.
				addLunaProvider();
				slotManager.login(slotLabel, slotPassword); // Performs C_Login
				System.out.println("LOGIN: SUCCESS");
				generateKeyPair();
			} else {
				System.out.println("ERROR: Slot with label " + slotLabel + " not found.");
				System.exit(1);
			}

			LunaSlotManager.getInstance().logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");

		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		} catch(Exception exception) {
			System.out.println("ERROR: "+ exception.getMessage());
		}
	}
}
