package com.mountainminds.openssl.compatibility;

import static org.junit.Assert.assertArrayEquals;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.junit.Before;
import org.junit.Test;

public class RsaEncryptionTest extends ExternalCommandTestBase {

	@Before
	public void before() throws Exception {
		super.before();

		// Private Key
		openssl("genrsa", "-out", "private.pem", "1024");
		proc.assertExitStatus();

		openssl("pkcs8", "-topk8", "-inform", "PEM", "-outform", "DER",
				"-nocrypt", "-in", "private.pem", "-out", "private.der");
		proc.assertExitStatus();

		// Public Key
		openssl("rsa", "-pubout", "-in", "private.pem", "-out", "public.pem");
		proc.assertExitStatus();

		openssl("rsa", "-pubin", "-pubout", "-outform", "DER", "-in",
				"public.pem", "-out", "public.der");
		proc.assertExitStatus();

	}

	@Test
	public void openssl2java() throws Exception {
		byte[] message = getSampleData(64);

		// Encode with OpenSSL
		openssl("rsautl", "-encrypt", "-pubin", "-inkey", "public.pem");
		proc.sendIn(message);
		byte[] encrypted = proc.getOutAsBytes();
		proc.assertExitStatus();

		// Decode with Java
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(
				readFile("private.der")));

		final Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decrypted = cipher.doFinal(encrypted);

		assertArrayEquals(message, decrypted);
	}

	@Test
	public void java2openssl() throws Exception {
		byte[] message = getSampleData(64);

		// Encode with Java
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(
				readFile("public.der")));

		final Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encrypted = cipher.doFinal(message);

		// Decode with OpenSSL
		openssl("rsautl", "-decrypt", "-inkey", "private.pem");
		proc.sendIn(encrypted);
		byte[] decrypted = proc.getOutAsBytes();
		proc.assertExitStatus();

		assertArrayEquals(message, decrypted);
	}

}
