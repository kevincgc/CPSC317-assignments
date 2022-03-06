package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

public class DNSMessage {
	public static final int MAX_DNS_MESSAGE_LENGTH = 512;
	public static final int QUERY = 0;
	private final Map<String, Integer> nameToPosition = new HashMap<>();
	private final Map<Integer, String> positionToName = new HashMap<>();
	private final ByteBuffer buffer;

	/**
	 * Initializes an empty DNSMessage with the given id.
	 *
	 * @param id The id of the message.
	 */
	public DNSMessage(short id) {
		this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
		setID(id);
		buffer.position(12);
	}

	/**
	 * Initializes a DNSMessage with the first length bytes of the given byte array.
	 *
	 * @param recvd  The byte array containing the received message
	 * @param length The length of the data in the array
	 */
	public DNSMessage(byte[] recvd, int length) {
		buffer = ByteBuffer.wrap(recvd, 0, length);
		buffer.put(recvd, 0, length);
		buffer.position(12);
	}

	/**
	 * Getters and setters for the various fixed size and fixed location fields of a
	 * DNSMessage
	 */
	public int getID() {
		int val = ((int) (buffer.get(0)) << 8 & 0xff00) | ((int) buffer.get(1) & 0xff);
		return val;
	}

	public void setID(int id) {
		buffer.put(0, (byte) (id >> 8 & 0xff));
		buffer.put(1, (byte) (id & 0xff));
	}

	public boolean getQR() {
		return (buffer.get(2) & 0x80) > 0;
	}

	public void setQR(boolean qr) {
		buffer.put(2, (byte) (qr ? buffer.get(2) | 0x80 : buffer.get(2) & 0x7f));
	}

	public boolean getAA() {
		return (buffer.get(2) & 0x04) > 0;
	}

	public void setAA(boolean aa) {
		buffer.put(2, (byte) (aa ? buffer.get(2) | 0x04 : buffer.get(2) & 0xfb));
	}

	public int getOpcode() {
		return ((int) buffer.get(2) & 0x78) >> 3;
	}

	public void setOpcode(int opcode) {
		byte b = (byte) ((buffer.get(2) & 0x87) | (opcode << 3 & 0x78));
		buffer.put(2, b);
	}

	public boolean getTC() {
		return (buffer.get(2) & 0x02) > 0;
	}

	public void setTC(boolean tc) {
		buffer.put(2, (byte) (tc ? buffer.get(2) | 0x02 : buffer.get(2) & 0xfd));
	}

	public boolean getRD() {
		return (buffer.get(2) & 0x01) > 0;
	}

	public void setRD(boolean rd) {
		buffer.put(2, (byte) (rd ? buffer.get(2) | 0x01 : buffer.get(2) & 0xfe));
	}

	public boolean getRA() {
		return (buffer.get(3) & 0x80) > 0;
	}

	public void setRA(boolean ra) {
		buffer.put(3, (byte) (ra ? buffer.get(3) | 0x80 : buffer.get(3) & 0x7f));
	}

	public int getRcode() {
		return buffer.get(3) & 0x0f;
	}

	public void setRcode(int rcode) {
		byte b = (byte) ((buffer.get(3) & 0xf0) | (rcode & 0x0f));
		buffer.put(3, b);
	}

	public int getQDCount() {
		return buffer.getShort(4);
	}

	public void setQDCount(int count) {
		buffer.putShort(4, (short) count);
	}

	public int getANCount() {
		return buffer.getShort(6);
	}

	public void setANCount(int count) {
		buffer.putShort(6, (short) count);
	}

	public int getNSCount() {
		return buffer.getShort(8);
	}

	public void setNSCount(int count) {
		buffer.putShort(8, (short) count);
	}

	public int getARCount() {
		return buffer.getShort(10);
	}

	public void setARCount(int count) {
		buffer.putShort(10, (short) count);
	}

	// TODO Del
	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	public int getBufferPosition() {
		return buffer.position();
	}

	/**
	 * Return the name at the current position() of the buffer. This method is
	 * provided for you, but you should ensure that you understand what it does and
	 * how it does it.
	 *
	 * The trick is to keep track of all the positions in the message that contain
	 * names, since they can be the target of a pointer. We do this by storing the
	 * mapping of position to name in the positionToName map.
	 *
	 * @return The decoded name
	 */
	public String getName() {
		// Remember the starting position for updating the name cache
		int start = buffer.position();
		int len = buffer.get() & 0xff;
		if (len == 0)
			return "";
		if ((len & 0xc0) == 0xc0) { // This is a pointer
			int pointer = ((len & 0x3f) << 8) | (buffer.get() & 0xff);
			String suffix = positionToName.get(pointer);
			assert suffix != null;
			positionToName.put(start, suffix);
			return suffix;
		}
		byte[] bytes = new byte[len];
		buffer.get(bytes, 0, len);
		String label = new String(bytes, StandardCharsets.UTF_8);
		String suffix = getName();
		String answer = suffix.isEmpty() ? label : label + "." + suffix;
		positionToName.put(start, answer);
		return answer;
	}

	/**
	 * The standard toString method that displays everything in a message.
	 * 
	 * @return The string representation of the message
	 */
	public String toString() {
		// Remember the current position of the buffer so we can put it back
		// Since toString() can be called by the debugger, we want to be careful to not
		// change
		// the position in the buffer. We remember what it was and put it back when we
		// are done.
		int end = buffer.position();
		final int DataOffset = 12;
		try {
			StringBuilder sb = new StringBuilder();
			sb.append("ID: ").append(getID()).append(' ');
			sb.append("QR: ").append(getQR()).append(' ');
			sb.append("OP: ").append(getOpcode()).append(' ');
			sb.append("AA: ").append(getAA()).append('\n');
			sb.append("TC: ").append(getTC()).append(' ');
			sb.append("RD: ").append(getRD()).append(' ');
			sb.append("RA: ").append(getRA()).append(' ');
			sb.append("RCODE: ").append(getRcode()).append(' ').append(dnsErrorMessage(getRcode())).append('\n');
			sb.append("QDCount: ").append(getQDCount()).append(' ');
			sb.append("ANCount: ").append(getANCount()).append(' ');
			sb.append("NSCount: ").append(getNSCount()).append(' ');
			sb.append("ARCount: ").append(getARCount()).append('\n');
			buffer.position(DataOffset);
			showQuestions(getQDCount(), sb);
			showRRs("Authoritative", getANCount(), sb);
			showRRs("Name servers", getNSCount(), sb);
			showRRs("Additional", getARCount(), sb);
			return sb.toString();
		} catch (Exception e) {
			e.printStackTrace();
			return "toString failed on DNSMessage";
		} finally {
			buffer.position(end);
		}
	}

	/**
	 * Add the text representation of all the questions (there are nq of them) to
	 * the StringBuilder sb.
	 *
	 * @param nq Number of questions
	 * @param sb Collects the string representations
	 */
	private void showQuestions(int nq, StringBuilder sb) {
		sb.append("Question [").append(nq).append("]\n");
		for (int i = 0; i < nq; i++) {
			DNSQuestion question = getQuestion();
			sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
		}
	}

	/**
	 * Add the text representation of all the resource records (there are nrrs of
	 * them) to the StringBuilder sb.
	 *
	 * @param kind Label used to kind of resource record (which section are we
	 *             looking at)
	 * @param nrrs Number of resource records
	 * @param sb   Collects the string representations
	 */
	private void showRRs(String kind, int nrrs, StringBuilder sb) {
		sb.append(kind).append(" [").append(nrrs).append("]\n");
		for (int i = 0; i < nrrs; i++) {
			ResourceRecord rr = getRR();
			sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
		}
	}

	/**
	 * Decode and return the question that appears next in the message. The current
	 * position in the buffer indicates where the question starts.
	 *
	 * @return The decoded question
	 */
	public DNSQuestion getQuestion() {
		String name = getName();
		RecordType rType = getRecordType();
		RecordClass rClass = getRecordClass();
		return new DNSQuestion(name, rType, rClass);
	}

	/**
	 * Decode and return the record type.
	 *
	 * @return The decoded record type
	 */
	public RecordType getRecordType() {
		buffer.position(buffer.position() + 1);
		return RecordType.getByCode(buffer.get());
	}

	/**
	 * Decode and return the record class.
	 *
	 * @return The decoded record class
	 */
	public RecordClass getRecordClass() {
		buffer.position(buffer.position() + 1);
		return RecordClass.getByCode(buffer.get());
	}

	/**
	 * Decode and return the time to live.
	 *
	 * @return The decoded TTL
	 */
	public int getTTL() {
		return buffer.getInt();
	}

	/**
	 * Decode and return the length of the RDATA field.
	 *
	 * @return The decoded length of the RDATA field
	 */
	public int getRDLength() {
		return (int) buffer.getShort() & 0xffff;
	}

	/**
	 * Decode and return the RDATA based on the input RDLENGTH.
	 *
	 * @return The decoded RDATA
	 */
	public byte[] getAddress(int length) {
		byte[] byteArray = new byte[length];
		buffer.get(byteArray, 0, length);
		return byteArray;
	}

	/**
	 * Decode and return the resource record that appears next in the message. The
	 * current position in the buffer indicates where the resource record starts.
	 *
	 * @return The decoded resource record
	 */
	public ResourceRecord getRR() {
		String name = getName();
		RecordType rType = getRecordType();
		RecordClass rClass = getRecordClass();
		DNSQuestion question = new DNSQuestion(name, rType, rClass);
		int ttl = getTTL();
		int rdLength = getRDLength();
		switch (rType) {
		case AAAA:
		case A:
			try {
				byte[] addressBytes = getAddress(rdLength);
				return new ResourceRecord(question, ttl, InetAddress.getByAddress(addressBytes));
			} catch (UnknownHostException e) {
				System.out.println("getRR error");
				e.printStackTrace();
			}
		case MX:
			short preference = buffer.getShort();
		case CNAME:
		case NS:
			String address = getName();
			return new ResourceRecord(question, ttl, address);
		default:
			System.out.println("getRR RecordType not AAAA, A, MX, CNAME or NS");
			byte[] byteArray = new byte[rdLength];
			buffer.get(byteArray, 0, rdLength);
			return new ResourceRecord(question, ttl, byteArrayToHexString(byteArray));
		}
	}

	/**
	 * Helper function that returns a hex string representation of a byte array. May
	 * be used to represent the result of records that are returned by a server but
	 * are not supported by the application (e.g., SOA records).
	 *
	 * @param data a byte array containing the record data.
	 * @return A string containing the hex value of every byte in the data.
	 */
	// TODO Change to private
	// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	public static String byteArrayToHexString(byte[] data) {
		return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
	}

	/**
	 * Add an encoded name to the message. It is added at the current position and
	 * uses compression as much as possible. Compression is accomplished by
	 * remembering the position of every added label.
	 *
	 * @param name The name to be added
	 */
	public void addName(String name) {
		String label;
		while (name.length() > 0) {
			Integer offset = nameToPosition.get(name);
			if (offset != null) {
				int pointer = offset;
				pointer |= 0xc000;
				buffer.putShort((short) pointer);
				return;
			} else {
				nameToPosition.put(name, buffer.position());
				int dot = name.indexOf('.');
				label = (dot > 0) ? name.substring(0, dot) : name;
				buffer.put((byte) label.length());
				for (int j = 0; j < label.length(); j++) {
					buffer.put((byte) label.charAt(j));
				}
				name = (dot > 0) ? name.substring(dot + 1) : "";
			}
		}
		buffer.put((byte) 0);
	}

	/**
	 * Add an encoded question to the message at the current position.
	 * 
	 * @param question The question to be added
	 */
	public void addQuestion(DNSQuestion question) {
		addRRQuestion(question);
		setQDCount(getQDCount() + 1);
	}

	/**
	 * Helper for addQuestion. Does not increment QD count.
	 * 
	 * @param question The question to be added
	 */
	public void addRRQuestion(DNSQuestion question) {
		addName(question.getHostName());
		addQType(question.getRecordType());
		addQClass(question.getRecordClass());
	}

	/**
	 * Add time to live to the message at the current position
	 * 
	 * @param ttl The time to live value
	 */
	public void addTTL(long ttl) {
		buffer.put((byte) ((ttl >> 24) & 0xff));
		buffer.put((byte) ((ttl >> 16) & 0xff));
		buffer.put((byte) ((ttl >> 8) & 0xff));
		buffer.put((byte) (ttl & 0xff));
	}

	/**
	 * Add an encoded resource record to the message at the current position.
	 * 
	 * @param rr      The resource record to be added
	 * @param section A string describing the section that the rr should be added to
	 */
	public void addResourceRecord(ResourceRecord rr, String section) {
		addRRQuestion(rr.getQuestion());
		addTTL(rr.getRemainingTTL());
		byte[] len;
		switch (rr.getRecordType()) {
		case AAAA:
		case A:
			len = new byte[] { 0x00, (byte) rr.getInetResult().getAddress().length };
			buffer.put(len);
			buffer.put(rr.getInetResult().getAddress());
			break;
		case MX:
			buffer.putShort((short) 0);
		case CNAME:
		case NS:
			int strLen = rr.getTextResult().length();
			buffer.put((byte) (strLen >> 8 & 0xff));
			buffer.put((byte) (strLen & 0xff));
			addName(rr.getTextResult());
			break;
		default:
			System.out.println("addResourceRecord Invalid RecordType");
		}
		switch (section) {
		case "answer":
			setANCount(getANCount() + 1);
			break;
		case "nameserver":
			setNSCount(getNSCount() + 1);
			break;
		case "additional":
			setARCount(getARCount() + 1);
			break;
		default:
			System.out.println("addResourceRecord Invalid Section String");
		}
	}

	/**
	 * Add an encoded type to the message at the current position.
	 * 
	 * @param recordType The type to be added
	 */
	private void addQType(RecordType recordType) {
		byte[] qType = new byte[] { 0x00, (byte) recordType.getCode() };
		buffer.put(qType);
	}

	/**
	 * Add an encoded class to the message at the current position.
	 * 
	 * @param recordClass The class to be added
	 */
	private void addQClass(RecordClass recordClass) {
		byte[] qClass = new byte[] { 0x00, (byte) recordClass.getCode() };
		buffer.put(qClass);
	}

	/**
	 * Return a byte array that contains all the data comprising this message. The
	 * length of the array will be exactly the same as the current position in the
	 * buffer.
	 * 
	 * @return A byte array containing this message's data
	 */
	public byte[] getUsed() {
		int start = buffer.position();
		byte[] byteArray = new byte[start];
		buffer.rewind();
		buffer.get(byteArray, 0, byteArray.length);
		buffer.position(start);
		return byteArray;
	}

	/**
	 * Returns a string representation of a DNS error code.
	 *
	 * @param error The error code received from the server.
	 * @return A string representation of the error code.
	 */
	public static String dnsErrorMessage(int error) {
		final String[] errors = new String[] { "No error", // 0
				"Format error", // 1
				"Server failure", // 2
				"Name error (name does not exist)", // 3
				"Not implemented (parameters not supported)", // 4
				"Refused" // 5
		};
		if (error >= 0 && error < errors.length)
			return errors[error];
		return "Invalid error message";
	}
}
