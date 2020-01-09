package tlsLight;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

public class SecurityHelpers {
	
	
	static byte [] generateRandomBytes(int size) {
		SecureRandom rand = new SecureRandom();
		byte[] randomBytes = new byte[size];
		rand.nextBytes(randomBytes);
		return randomBytes;
	}
	
	static public byte [] joinArrays(byte [] array1, byte [] array2) {
		byte [] ret = new byte [array1.length + array2.length];
		copyBytes(array1, ret, 0);
		copyBytes(array2, ret, array1.length);
		return ret;
	}
	
	static public byte[] copyBytes(byte [] original, byte [] newArr, int start) {
		for(int i = 0; i < original.length; i++) {
			newArr[start] = original[i];
			start++;
		}
		
		return newArr;
	}
	/** end is ! enclusive [start, end); **/
	static public byte [] getSubArray(byte [] original, int start, int end) {
		byte [] ret = new byte [end - start];
		for(int i = 0; i < ret.length; i++) {
			ret[i] = original[start];
			start++;
		}
		return ret;
	}
	
	static public void printByteArr(byte [] arr) {
		for(int i = 0; i < arr.length; i++) {
			System.out.println(i + ": " + arr[i]);
		}
	}
	
	static public byte [] hmac(byte [] key, byte [] data) throws InvalidKeyException, NoSuchAlgorithmException {
		Mac mac = Mac.getInstance("HmacSHA256");
		SecretKeySpec keySpec = new SecretKeySpec(key, "RSA");
		mac.init(keySpec);
		byte [] input = new byte [key.length + data.length + 1];
		copyBytes(key, input, 0);
		copyBytes(data, input, key.length);
		input[input.length-1] = 1;
		byte [] hmac = mac.doFinal(input);
		return hmac;
	}
	
	static byte [] hdkfExpand(byte [] key, byte [] tag ) throws NoSuchAlgorithmException, InvalidKeyException {
		byte [] hmac = hmac(key, tag);
		byte [] subKey = new byte [16];
		for(int i = 0; i < subKey.length; i++) {
			subKey[i] = hmac[i];
		}
		return subKey;
	}
	
	static Cipher initEncryptMode(byte [] keyBytes, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
		return cipher;
	}
	
	static Cipher initDecrypttMode(byte [] keyBytes, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
		return cipher;
	}
	
	static byte [] encryptMessage(byte [] keyBytes, byte[] macKey, IvParameterSpec iv, byte [] file ) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
		byte [] hmac = hmac(macKey, file);
		System.out.println("HMAC SIZE: " + hmac.length);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
		byte [] plainText = joinArrays(file, hmac);
		byte[] cipherText = cipher.doFinal(plainText);
		byte [] message = joinArrays(cipherText, hmac);
		return message;
	}
	
	static byte [] decryptMessage(byte [] keyBytes, byte[] macKey, IvParameterSpec iv, byte [] data ) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
		byte [] encrpytedPayload = getSubArray(data, 0, data.length - 32);
		byte[] cipherText = cipher.doFinal(encrpytedPayload);
		System.out.println("Payload Len: " + cipherText.length);
		byte [] message = getSubArray(cipherText, 0, cipherText.length - 32);
		return message;
		
	}
	
	
}

