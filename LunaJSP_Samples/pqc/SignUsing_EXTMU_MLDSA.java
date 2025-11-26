        /*********************************************************************************\
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
	- This sample demonstrates how to generate a ML-DSA keypair using LunaProvider and use it to sign data.
	- Keypair generated using this sample is ephemeral, i.e. a session keypair.
	- This sample requires LunaClient 10.9.1 to execute.
	- This sample uses a 64-byte dummy mu value to demonstrates digital signing using CKM_EXTMU_ML_DSA mechanism.
*/


import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class SignUsing_EXTMU_MLDSA {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair mldsaKeyPair = null;
	private static final String MLDSAPARAM = "ML-DSA-65";
	private static final String PROVIDER = "LunaProvider";
	private static final String EXTERNAL_MU = "90a6bea52f99432fcfb754e49b3bf6667ab7072a2248378e7afaa4bad813ce68"; // Dummy external mu value.
	private static byte[] signature = null;


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ SignUsing_EXTMU_MLDSA ]\n");
		System.out.println("Usage-");
		System.out.println("java SignUsing_EXTMU_MLDSA <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java SignUsing_EXTMU_MLDSA myPartition userpin\n");
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


	// generates ML-DSA keypair
	private static void generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(MLDSAPARAM, PROVIDER);
		mldsaKeyPair = keyPairGen.generateKeyPair();
		System.out.println("MLDSA-65 keypair generated.");
	}


	// signs the plaintext using CKM_EXTMU_ML_DSA mechanism.
	private static void signData() throws Exception {
		Signature sign = Signature.getInstance("EXTMU_ML-DSA", PROVIDER);
		sign.initSign(mldsaKeyPair.getPrivate());
		sign.update(EXTERNAL_MU.getBytes());
		signature = sign.sign();
		System.out.println("Plaintext signed.");
	}


	// verifies the signature.
	private static void verifyData() throws Exception {
		Signature verify = Signature.getInstance("EXTMU_ML-DSA", PROVIDER);
		verify.initVerify(mldsaKeyPair.getPublic());
		verify.update(EXTERNAL_MU.getBytes());
		if(verify.verify(signature)) {
			System.out.println("Signature verified.");
		} else {
			System.out.println("Signature verification failed.");
		}
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
				signData();
				verifyData();
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
