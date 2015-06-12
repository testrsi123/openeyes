package com.rsys.openeyes.utils;

import static org.mockito.Mockito.when;

import javax.crypto.Cipher;

import mockit.MockUp;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.acn.omi.util.PasswordEncryptor;

public class PasswordEncryptorTest{

	private Cipher cipher;
	
	@Test
	public void encryptAndDecryptTest(){
		
		String password = "admin123";
		
		String encryptedPassword = PasswordEncryptor.encrypt(password);
		String decryptedPassword = PasswordEncryptor.decrypt(encryptedPassword);

	}
	
	@Test
	public void make4DigitPinTest(){
		Long pin = 00111L;
		String newPin = PasswordEncryptor.make4DigitPinStartWithZero(pin);
		
		Assert.assertNotNull(newPin);
	}
	
	@Test
	public void encryptAndDecryptNullPasswordTest(){
		String encryptedPassword = PasswordEncryptor.encrypt(null);
		String decryptedPassword = PasswordEncryptor.decrypt(null);
		
		Assert.assertNull(encryptedPassword);
		Assert.assertNull(decryptedPassword);
	}
	
	@Test
	public void encryptAndDecryptBlankPasswordTest(){
		String encryptedPassword = PasswordEncryptor.encrypt("");
		String decryptedPassword = PasswordEncryptor.decrypt("");
		
		Assert.assertNull(encryptedPassword);
		Assert.assertNull(decryptedPassword);
	}
	
	@Test
	public void encryptExceptionTest(){
		String password = "admin123";
		
		new MockUp<Cipher>(){
			@mockit.Mock
			public Cipher getInstance(String transformation){
				return cipher;
			}
		};
		
		try {
			when(cipher.doFinal(password.getBytes("UTF-8"))).thenThrow(new NullPointerException("MockException"));
		} catch (Exception e) {
			
		}
		
		String encryptedPassword = PasswordEncryptor.encrypt(password);
		
		Assert.assertNull(encryptedPassword);
	}
}
