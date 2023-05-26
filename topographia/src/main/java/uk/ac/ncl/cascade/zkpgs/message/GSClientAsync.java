package uk.ac.ncl.cascade.zkpgs.message;

import uk.ac.ncl.cascade.zkpgs.store.URN;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class GSClientAsync implements IMessagePartner {
	private final int port;
	private final String hostAddress;
	private static final int BUFFER_SIZE = 4096;
	public static AsynchronousSocketChannel client;
	private static GSMessage message = new GSMessage();
	private final ConcurrentHashMap<String, GSMessage> messages = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<String, GSMessage> messagesReceived = new ConcurrentHashMap<>();
	private AsynchronousSocketChannel clientChannel;

	public GSClientAsync(final String hostAddress, final int port) {
		this.hostAddress = hostAddress;
		this.port = port;
	}

	/**
	 * @throws IOException
	 */
	@Override
	public void init() throws IOException {
		clientChannel = AsynchronousSocketChannel.open();
		Future<Void> future = clientChannel.connect(new InetSocketAddress(hostAddress, port));
		try {
			future.get(); // Wait for the connection to complete
		} catch (ExecutionException | InterruptedException e) {
			throw new RuntimeException(e);
		}
		client = clientChannel;

	}

	public void send(GSMessage message) throws ClassNotFoundException {
		try {
//			AsynchronousSocketChannel clientChannel = AsynchronousSocketChannel.open();
//			Future<Void> future = clientChannel.connect(new InetSocketAddress(hostAddress, port));
//			future.get(); // Wait for the connection to complete
//			client = clientChannel;
//			System.out.println("Connected to server at " + hostAddress + ":" + port);
			System.out.println("Send message " + message.getType() + " to server at " + hostAddress + ":" + port + " from " + clientChannel.getLocalAddress().toString());
			sendMessage(clientChannel, message);
		} catch (IOException e) {
			System.err.println("Error sending " + e);
		}
//		try {
//			Thread.currentThread().join();
//		} catch (InterruptedException e) {
//			throw new RuntimeException(e);
//		}
	}

	public void receive(AsynchronousSocketChannel clientChannel) throws IOException, ExecutionException, InterruptedException, ClassNotFoundException {
		if (clientChannel.isOpen()) {
			readMessage(clientChannel);
		} else {

//			clientChannel = AsynchronousSocketChannel.open();
//			Future<Void> future = client.connect(new InetSocketAddress(hostAddress, port));
//			future.get(); // Wait for the connection to complete
			readMessage(clientChannel);
		}
	}

	public void readMessage(AsynchronousSocketChannel clientChannel) throws ExecutionException, InterruptedException, IOException, ClassNotFoundException {
		ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
//		buffer.flip();
//		buffer.clear();
		clientChannel.read(buffer, null, new CompletionHandler<Integer, Void>() {
			@Override
			public void completed(Integer bytesRead, Void attachment) {
				if (bytesRead == -1) {
					// Client disconnected
					try {
						System.out.println("Client disconnected: " + clientChannel.getRemoteAddress());
						clientChannel.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				} else {

					buffer.flip();
					try {
						message = GSMessage.deserialize(buffer.array());
						System.out.println("completed message: " + message.getPayload());
						handleMessage(clientChannel, message);
					} catch (IOException | ClassNotFoundException e) {
						throw new RuntimeException(e);
					}
				}

				// Once the previous read is done, you can initiate a new read here
//				buffer.clear();
//				clientChannel.read(buffer, null, this);
			}

			@Override
			public void failed(Throwable exc, Void attachment) {
				System.out.println("Read failed: " + exc.getMessage());
//				try {
//					clientChannel.close();
//				} catch (IOException e) {
//					e.printStackTrace();
//				}
			}
		});
	}

	private void handleMessage(AsynchronousSocketChannel clientChannel,
							   GSMessage message) throws ClassNotFoundException {
		GSClientAsync.message = message;

		System.out.println("handle message type: " + message.getType());

		switch (message.getType()) {
			case CONNECT:
				System.out.println("Client connected: " + message.getPayload());
				break;
			case DISCONNECT:
				System.out.println("Client disconnected: " + message.getPayload());
//				clients.remove(clientChannel.getRemoteAddress().toString());
//				closeChannel(clientChannel);
				break;
			case DATA:
				System.out.println("handle Received message: " + message.getPayload());
				messagesReceived.put("data", message);
//				broadcastMessage(clientChannel, message);
				break;
			case INIT:
				System.out.println("Initialization Received message: " + message.getPayload());
				messagesReceived.put("init", message);
				HashMap<URN, Object> messageElements2 = new HashMap<URN, Object>();
				messageElements2.put(URN.createUnsafeZkpgsURN("urn3"), "dataFromClient2_register");
				messageElements2.put(URN.createUnsafeZkpgsURN("urn4"), "dataFromClient2_register");
				GSMessage message2 = new GSMessage(GSMessage.MessageType.REGISTER, messageElements2);
				send(message2);
				break;
			case REGISTER:
				System.out.println("Registration Received message: " + message.getPayload());
				messagesReceived.put("register", message);
				HashMap<URN, Object> messageElements3 = new HashMap<URN, Object>();
				messageElements3.put(URN.createUnsafeZkpgsURN("urn3"), "dataFromClient2_certify");
				messageElements3.put(URN.createUnsafeZkpgsURN("urn4"), "dataFromClient2_certify");
				GSMessage message3 = new GSMessage(GSMessage.MessageType.CERTIFY, messageElements3);
				send(message3);
				break;
			case CERTIFY:
				System.out.println("Certification Received message: " + message.getPayload());
				messagesReceived.put("certify", message);
				HashMap<URN, Object> messageElements4 = new HashMap<URN, Object>();
				messageElements4.put(URN.createUnsafeZkpgsURN("urn3"), "dataFromClient2_attest");
				messageElements4.put(URN.createUnsafeZkpgsURN("urn4"), "dataFromClient2_attest");
				GSMessage message4 = new GSMessage(GSMessage.MessageType.ATTEST, messageElements4);
				send(message4);
				break;
			case ATTEST:
				System.out.println("Attestation Received message: " + message.getPayload());
				messagesReceived.put("attest", message);
				HashMap<URN, Object> messageElements5 = new HashMap<URN, Object>();
				messageElements5.put(URN.createUnsafeZkpgsURN("urn3"), "dataFromClient2_proof_of_binding");
				messageElements5.put(URN.createUnsafeZkpgsURN("urn4"), "dataFromClient2_proof_of_binding");
				GSMessage message5 = new GSMessage(GSMessage.MessageType.ATTEST, messageElements5);
				send(message5);
				break;
			default:
				break;
		}
	}

	private void sendMessage(AsynchronousSocketChannel clientChannel, GSMessage message) {
		byte[] bytes = new byte[0];
		try {
			bytes = message.serialize();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		ByteBuffer buffer = ByteBuffer.wrap(bytes);
		byte[] finalBytes = bytes;
		clientChannel.write(buffer, null, new CompletionHandler<Integer, Void>() {
			@Override
			public void completed(Integer bytesWritten, Void attachment) {
				if (bytesWritten < finalBytes.length) {
					clientChannel.write(buffer, null, this);
				}
				try {
					receive(clientChannel);
				} catch (ExecutionException | InterruptedException |
						 IOException | ClassNotFoundException e) {
					throw new RuntimeException(e);
				}

//				readResponse(clientChannel);
			}

			@Override
			public void failed(Throwable exc, Void attachment) {
				System.err.println("Failed to send message: " + exc.getMessage());
			}
		});


	}

	private AsynchronousSocketChannel connectToServer(String address, int port) throws IOException, ExecutionException, InterruptedException {
		AsynchronousSocketChannel clientChannel = AsynchronousSocketChannel.open();
		Future<Void> future = clientChannel.connect(new InetSocketAddress(hostAddress, port));
		future.get(); // Wait for the connection to complete
		System.out.println("Connected to server at " + address + ":" + port);
		return clientChannel;
	}

	private void readResponse(AsynchronousSocketChannel clientChannel) {
		ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
		clientChannel.read(buffer, null, new CompletionHandler<Integer, Void>() {
			@Override
			public void completed(Integer result, Void attachment) {

				buffer.flip();
				try {
					message = GSMessage.deserialize(buffer.array());

				} catch (IOException | ClassNotFoundException e) {
					throw new RuntimeException(e);
				}
				System.out.println("Received from server: " + message);
			}

			@Override
			public void failed(Throwable exc, Void attachment) {
				System.out.println("Failed to read response");
				exc.printStackTrace();
			}
		});
	}

	/**
	 * @throws IOException
	 */
	@Override
	public void close() throws IOException {
	}

	public GSMessage getMessage() {
		return message;
	}
}
