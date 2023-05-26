package uk.ac.ncl.cascade.zkpgs.message;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import java.io.IOException;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;

@Execution(ExecutionMode.CONCURRENT)
class GSClientAsyncTest {
	private GSClientAsync clientAsync;

	@BeforeEach
	void setUp() {
		clientAsync = new GSClientAsync("localhost", 1233);
	}

	@Test
	void init() throws IOException, ClassNotFoundException {
		System.out.println("client1");
		clientAsync.init();

		HashMap<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createUnsafeZkpgsURN("urn1"), "dataFromClient_init");
		messageElements.put(URN.createUnsafeZkpgsURN("urn2"), "dataFromClient_init");
		GSMessage message = new GSMessage(GSMessage.MessageType.INIT, messageElements);
		clientAsync.send(message);
	}

	@Test
	void init2() throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
		System.out.println("client2");
		clientAsync.init();

		HashMap<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createUnsafeZkpgsURN("urn1"), "dataFromClient_init");
		messageElements.put(URN.createUnsafeZkpgsURN("urn2"), "dataFromClient_init");
		GSMessage message = new GSMessage(GSMessage.MessageType.INIT, messageElements);
		clientAsync.send(message);
	}

	@Test
	void init3() throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
		System.out.println("client3");
		clientAsync.init();

		HashMap<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createUnsafeZkpgsURN("urn1"), "dataFromClient_init");
		messageElements.put(URN.createUnsafeZkpgsURN("urn2"), "dataFromClient_init");
		GSMessage message = new GSMessage(GSMessage.MessageType.INIT, messageElements);
		clientAsync.send(message);
	}

	@Test
	void init4() throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
		System.out.println("client4");
		clientAsync.init();

		HashMap<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createUnsafeZkpgsURN("urn1"), "dataFromClient_init");
		messageElements.put(URN.createUnsafeZkpgsURN("urn2"), "dataFromClient_init");
		GSMessage message = new GSMessage(GSMessage.MessageType.INIT, messageElements);
		clientAsync.send(message);
	}
}