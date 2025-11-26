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
	- This sample demonstrates how to generate a ML-DSA keypair using LunaProvider and use it to sign data.
	- Keypair generated using this sample is ephemeral, i.e. a session keypair.
	- This sample requires LunaClient 10.9.1 to execute.
	- This sample uses CKM_HASH_ML_DSA mechanism to generate a hash based signature.
*/


import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;
import java.security.MessageDigest;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.param.LunaMLDSAParameterSpec;
import com.safenetinc.luna.provider.param.LunaMLDSAParameterSpec.HEDGE_VARIANT;
import com.safenetinc.luna.exception.*;


public class SignUsing_HASH_MLDSA {

	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static KeyPair mldsaKeyPair = null;
	private static final String MLDSAPARAM = "ML-DSA-65"; // Security parameter to use for generating ML-DSA keypair
	private static final String HASHALGORITHM = "SHA3_256"; // Hash algorithm to use. Accepted values >> SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512.
	private static final String PROVIDER = "LunaProvider";
	private static final String PLAINTEXT = "Hello World, I've been waiting for the chance to see your face."; // Plaintext to sign.
	private static AlgorithmParameterSpec mldsaSpec = null;
	private static byte[] signature = null;
	private static byte[] messageDigest = null;


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println("[ SignUsing_HASH_MLDSA ]\n");
		System.out.println("Usage-");
		System.out.println("java SignUsing_HASH_MLDSA <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java SignUsing_HASH_MLDSA myPartition userpin\n");
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


	// Computes hash
	private static void computeHash() throws Exception {
		MessageDigest md = MessageDigest.getInstance(HASHALGORITHM);
		md.update(PLAINTEXT.getBytes());
		messageDigest = md.digest();
	}


	// Initialises Algorithm Parameters CKM_HASH_ML_DSA
	private static void initParam() {
		byte []context = "1234567812345678".getBytes();
		LunaMLDSAParameterSpec.HEDGE_VARIANT hedgeVariant = LunaMLDSAParameterSpec.HEDGE_VARIANT.DETERMINISTIC_REQUIRED;
		mldsaSpec = new LunaMLDSAParameterSpec(HEDGE_VARIANT.DETERMINISTIC_REQUIRED, context, HASHALGORITHM);
	}


	// signs the plaintext using CKM_HASH_ML_DSA mechanism.
	private static void signData() throws Exception {
		initParam();
		Signature sign = Signature.getInstance("HASH_ML-DSA", PROVIDER);
		sign.setParameter(mldsaSpec);
		sign.initSign(mldsaKeyPair.getPrivate());
		sign.update(messageDigest);
		signature = sign.sign();
		System.out.println("Plaintext signed.");
	}


	// verifies the signature.
	private static void verifyData() throws Exception {
		Signature verify = Signature.getInstance("HASH_ML-DSA", PROVIDER);
		verify.setParameter(mldsaSpec);
		verify.initVerify(mldsaKeyPair.getPublic());
		verify.update(messageDigest);
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
				computeHash();
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
