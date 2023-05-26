package uk.ac.ncl.cascade.zkpgs.message;

import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

import javax.json.JsonObject;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static uk.ac.ncl.cascade.zkpgs.util.JsonUtils.mapToJson;

public class GSMessage implements Serializable {

	private static final long serialVersionUID = -8931520272759188134L;

	Map<URN, Object> messageElements;
	public enum MessageType {
		CONNECT, DISCONNECT, DATA, ERROR, INIT, REGISTER, CERTIFY, ATTEST
	}

	private MessageType type;
	public GSMessage() {
		messageElements = new HashMap<URN, Object>();
	}
	public GSMessage(MessageType type, Map<URN, Object> messageElements){
		this.type = type;
		this.messageElements = messageElements;
	}

	public MessageType getType() {
		return type;
	}

	public Map<URN, Object> getPayload() {
		return this.messageElements;
	}

	public GSMessage(Map<URN, Object> messageElements) {
		this.messageElements = messageElements;
	}

	public Map<URN, Object> getMessageElements() {
		return this.messageElements;
	}

	public JsonObject getJsonMessage() {
		return mapToJson(this.messageElements);
	}
	public byte[] serialize() throws IOException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		ObjectOutputStream msgStream = new ObjectOutputStream(byteArrayOutputStream);
		msgStream.writeObject(this);
		msgStream.close();
		return byteArrayOutputStream.toByteArray();
	}

	public static GSMessage deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
		ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);

		Object message = objectInputStream.readObject();
		objectInputStream.close();
		return (GSMessage) message;
	}

}

