        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************

        OBJECTIVE :
	- This sample demonstrates how to compute HMAC-SHA1 signature.
	- Login will use Crypto-Officer password.
	- This sample uses CKM_SHA_1_HMAC mechanism, which in java security is known as "HMACSHA1".
*/



import java.security.Security;
import java.security.MessageDigest;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;
import com.safenetinc.luna.LunaUtils;


public class HMACUsing_SHA1 {

	private static String slotLabel = null;
	private static String slotPassword = null;
	private static byte[] signature = null;
	private static SecretKey aesKey = null;
	private static final int KEY_SIZE = 256;
	private static final String PLAINTEXT = "Hello World, I've been waiting for the chance to see your face.";
	private static final String PROVIDER = "LunaProvider";

	private static void printUsage() {
		System.out.println(" [ HMACUsing_SHA1 ]\n");
		System.out.println("Usage-");
		System.out.println("java HMACUsing_SHA1 <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java HMACUsing_SHA1 myPartition userpin\n");
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


        // Generate AES key.
        private static void generateAESKey() throws Exception {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", PROVIDER);
                keyGenerator.init(KEY_SIZE);
                aesKey = keyGenerator.generateKey();
                System.out.println("AES key generated.");
        }

	// To compute HMAC-SHA1
	private static void generateCMAC() throws Exception {
		Mac mac = Mac.getInstance("HMACSHA1", PROVIDER);
		mac.init(aesKey);
		mac.update(PLAINTEXT.getBytes());
		signature = mac.doFinal();
		System.out.println("HMAC-SHA-1: " + LunaUtils.getHexString(signature, false));
    	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			LunaSlotManager.getInstance().login(slotPassword); // Performs C_Login
			System.out.println("LOGIN: SUCCESS");
			addLunaProvider();
			generateAESKey();
			generateCMAC();
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
