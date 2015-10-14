package com.mountainminds.openssl.compatibility;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Test;

/**
 * Exchanging Public/Private Keys between OpenSSL and Java.
 */
public class RsaKeysTest extends ExternalCommandTestBase {

	@Test
	public void readOpensslKeysWithJava() throws Exception {
		openssl("genrsa", "1024");
		String privateKeyPEM = proc.getOutAsString();
		proc.assertExitStatus();

		openssl("rsa", "-pubout");
		proc.sendIn(privateKeyPEM);
		String publicKeyPEM = proc.getOutAsString();
		proc.assertExitStatus();

		// Convert Private Key to PKCS#8 format for Java
		openssl("pkcs8", "-topk8", "-inform", "PEM", "-outform", "DER",
				"-nocrypt");
		proc.sendIn(privateKeyPEM);
		byte[] privateKeyPKCS8 = proc.getOutAsBytes();
		proc.assertExitStatus();

		// Convert Public Key to DER Format for Java
		openssl("rsa", "-pubin", "-pubout", "-outform", "DER");
		proc.sendIn(publicKeyPEM);
		byte[] publicKeyDER = proc.getOutAsBytes();
		proc.assertExitStatus();

		KeyFactory kf = KeyFactory.getInstance("RSA");

		// Read Private Key with Java
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(
				privateKeyPKCS8);
		kf.generatePrivate(privateSpec);

		// Read Public Key with Java
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyDER);
		kf.generatePublic(publicSpec);
	}

	@Test
	public void readJavaKeysWithOpenssl() throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair keypair = keyGen.genKeyPair();
		byte[] privateKeyPKCS8 = keypair.getPrivate().getEncoded();
		byte[] publicKeyDER = keypair.getPublic().getEncoded();

		// Convert Private Key to PEM Format for OpenSSL
		openssl("pkcs8", "-inform", "DER", "-outform", "PEM", "-nocrypt");
		proc.sendIn(privateKeyPKCS8);
		String privateKeyPEM = proc.getOutAsString();
		proc.assertExitStatus();

		// Convert Public Key to PEM Format for OpenSSL
		openssl("rsa", "-pubin", "-inform", "DER", "-outform", "PEM");
		proc.sendIn(publicKeyDER);
		String publicKeyPEM = proc.getOutAsString();
		proc.assertExitStatus();

		// Dump Private Key
		openssl("rsa", "-text");
		proc.sendIn(privateKeyPEM);
		System.out.println(proc.getOutAsString());
		proc.assertExitStatus();

		// Dump Public Key
		openssl("rsa", "-pubin", "-text");
		proc.sendIn(publicKeyPEM);
		System.out.println(proc.getOutAsString());
		proc.assertExitStatus();
	}

}
