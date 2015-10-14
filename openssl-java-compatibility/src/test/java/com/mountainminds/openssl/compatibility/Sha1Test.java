package com.mountainminds.openssl.compatibility;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.MessageDigest;

import org.junit.Test;

public class Sha1Test extends ExternalCommandTestBase {

	@Test
	public void compareBinarySignature() throws Exception {
		byte[] data = getSampleData(0x1000);

		// OpenSSL
		openssl("sha1", "-binary");
		proc.sendIn(data);
		byte[] opensslHash = proc.getOutAsBytes();

		// Java
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] javaHash = md.digest(data);

		assertArrayEquals(opensslHash, javaHash);
	}

	@Test
	public void compareHexSignature() throws Exception {
		byte[] data = getSampleData(0x1000);

		// OpenSSL
		openssl("sha1", "-hex");
		proc.sendIn(data);
		String opensslHash = proc.getOutAsString().trim();

		// Java
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		String javaHash = toHex(md.digest(data));

		assertEquals(opensslHash, javaHash);
	}

}
