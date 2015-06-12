package com.mountainminds.openssl.compatibility;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;

/**
 * Wrapper for OpenSSL process with convenience methods.
 */
public class OpenSSLProcess {

	private Process proc;

	OpenSSLProcess(Process proc) {
		this.proc = proc;
	}

	public void assertExitStatus() throws InterruptedException {
		assertExitStatus(0);
	}

	public void assertExitStatus(int expectedStatus)
			throws InterruptedException {
		assertEquals(expectedStatus, proc.waitFor());
	}

	public void sendIn(byte[] data) throws IOException {
		OutputStream out = proc.getOutputStream();
		out.write(data);
		out.close();
	}

	public String getOutAsString() throws IOException {
		return getAsString(proc.getInputStream());
	}

	public String getErrAsString() throws IOException {
		return getAsString(proc.getErrorStream());
	}

	public void sendIn(String text) throws IOException {
		Writer writer = new OutputStreamWriter(proc.getOutputStream());
		writer.write(text);
		writer.flush();
	}

	private String getAsString(InputStream in) throws IOException {
		InputStreamReader reader = new InputStreamReader(in);
		StringWriter buffer = new StringWriter();
		int c;
		while ((c = reader.read()) != -1) {
			buffer.write(c);
		}
		return buffer.toString();
	}

	public byte[] getOutAsBytes() throws IOException {
		return getAsBytes(proc.getInputStream());
	}

	public byte[] getErrAsBytes() throws IOException {
		return getAsBytes(proc.getErrorStream());
	}

	private byte[] getAsBytes(InputStream in) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int b;
		while ((b = in.read()) != -1) {
			buffer.write(b);
		}
		return buffer.toByteArray();
	}

}
