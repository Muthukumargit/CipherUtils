package com.cipher;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

public class CipherUtils implements ApplicationContextInitializer<ConfigurableApplicationContext> {
	
	@Autowired
	private Environment environment;

	@Override
	public void initialize(ConfigurableApplicationContext applicationContext) {
		 	ConfigurableEnvironment env= applicationContext.getEnvironment();
		 	MutablePropertySources sources = env.getPropertySources();
		 	
		 	String key = env.getProperty("cipher.key");
			String iv = env.getProperty("cipher.iv");
			if(key == null || iv == null) {
				System.err.println("[CipherUtils] Missing cipher.key or cipher.iv in properties.");
				return;
			}
		 	for(PropertySource<?> prop:sources) {
		 		if(prop instanceof EnumerablePropertySource) {
		 			 Map<String, Object> decryptedMap = new HashMap<>();
		 			EnumerablePropertySource<?> eps= (EnumerablePropertySource<?>) prop; 
		 			
		 			for(String value:eps.getPropertyNames()) {
		 				Object propValue= eps.getProperty(value);
		 				if(propValue instanceof String && ((String) propValue).startsWith("${cipher_decrypt}")) {
		 					try {
		 						String encrypyted = ((String) propValue).replace("${cipher_decrypt}", "");
		 						String decrypted= Decrypt(encrypyted, key, iv);
								decryptedMap.put(value, decrypted);
							} catch (Exception e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
		 				}
		 			}
		 			if (!decryptedMap.isEmpty()) {
	                    sources.addFirst(new MapPropertySource("decrypted", decryptedMap));
	                }
		 		}
		 		
		 		
		 	}
		 		
	}
	
	private String Decrypt(String encrpytedTxt, String key, String iv) throws Exception {
		try {
			SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
			IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			byte[] decrypt = cipher.doFinal(Base64.getDecoder().decode(encrpytedTxt));
			return new String(decrypt);
		} catch (Exception e) {
			System.out.println("error while encrypting ::" + e.getMessage());
			e.printStackTrace();
			return encrpytedTxt;
		}
	}
	
	public String EncryptionForEmail(String plainText) {
		System.out.println("Entered into EncryptionForEmail");
		String key=environment.getProperty("email.secret.key");
		String iv=environment.getProperty("email.secret.iv");;
		
		try {
			SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
			IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8")); // convert plaintext to bytes
	        return Base64.getEncoder().encodeToString(encryptedBytes); // return as Base64 string
		} catch (Exception e) {
			System.out.println("error while encrypting ::" + e.getMessage());
			e.printStackTrace();
			return plainText;
		}
	}
	
		public String DecryptionForEmail(String encryptedText) {
		System.out.println("Entered into DecryptionForEmail");
		String key=environment.getProperty("email.secret.key");
		String iv=environment.getProperty("email.secret.iv");;
		
		try {
			SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
			IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			  byte[] decodedBytes = Base64.getDecoder().decode(encryptedText); // decode from Base64
		      byte[] decryptedBytes = cipher.doFinal(decodedBytes); // decrypt
		      return new String(decryptedBytes, "UTF-8");
		} catch (Exception e) {
			System.out.println("error while encrypting ::" + e.getMessage());
			e.printStackTrace();
			return encryptedText;
		}
	}

}
