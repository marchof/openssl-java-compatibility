package com.mountainminds.openssl.compatibility;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Test;

public class RsaTest extends ExternalCommandTestBase {

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

		// Read Keys with Java

		KeyFactory kf = KeyFactory.getInstance("RSA");

		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(
				privateKeyPKCS8);
		kf.generatePrivate(privateSpec);

		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyDER);
		kf.generatePublic(publicSpec);
	}

	@Test
	public void readJavaKeysWithOpenssl() throws Exception {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair keypair = keyGen.genKeyPair();
		byte[] publicKeyDER = keypair.getPublic().getEncoded();
		byte[] privateKeyPKCS8 = keypair.getPrivate().getEncoded();

		openssl("rsa", "-text", "-pubin", "-inform", "DER");
		proc.sendIn(publicKeyDER);
		proc.assertExitStatus();

		// TODO: Read Private Key with OpenSSL
	}

}
