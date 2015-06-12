package com.mountainminds.openssl.compatibility;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

/**
 * Test base class with utilities to launch external openssl processes.
 */
public abstract class ExternalCommandTestBase {

	protected Random random;

	protected OpenSSLProcess proc;

	@Rule
	public final TemporaryFolder workdir = new TemporaryFolder();

	@Before
	public void before() throws Exception {
		// deterministic "random" data
		random = new Random(42);
	}

	@After
	public void after() throws Exception {
		if (proc != null) {
			proc.assertExitStatus();
		}
	}

	protected OpenSSLProcess openssl(String... args) throws IOException {
		String[] command = new String[args.length + 1];
		command[0] = "openssl";
		System.arraycopy(args, 0, command, 1, args.length);
		proc = new OpenSSLProcess(Runtime.getRuntime().exec(command, null,
				workdir.getRoot()));
		return proc;
	}

	protected OpenSSLProcess exec(String... args) throws IOException {
		proc = new OpenSSLProcess(Runtime.getRuntime().exec(args));
		return proc;
	}

	protected byte[] getSampleData(int len) {
		byte[] data = new byte[len];
		random.nextBytes(data);
		return data;
	}

	protected String toHex(byte[] data) {
		StringBuilder buffer = new StringBuilder();
		for (byte b : data) {
			buffer.append(Character.forDigit(0x0f & (b >> 4), 16));
			buffer.append(Character.forDigit(0x0f & b, 16));
		}
		return buffer.toString();
	}

	protected String file(String localname) {
		return new File(workdir.getRoot(), localname).getAbsolutePath();
	}

	protected byte[] readFile(String localname) throws IOException {
		File file = new File(workdir.getRoot(), localname);
		InputStream in = new FileInputStream(file);
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int b;
		while ((b = in.read()) != -1) {
			buffer.write(b);
		}
		in.close();
		return buffer.toByteArray();
	}

}
