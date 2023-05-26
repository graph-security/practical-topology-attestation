package uk.ac.ncl.cascade.zkpgs.message;

import uk.ac.ncl.cascade.zkpgs.store.URN;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 *
 */
public class GSServerAsync implements IMessagePartner {
	private static final int BUFFER_SIZE = 4096;
	private final int port;
	private final ConcurrentHashMap<String, AsynchronousSocketChannel> clients = new ConcurrentHashMap<>();

	public ConcurrentHashMap<String, AsynchronousSocketChannel> getClients() {
		return clients;
	}

	public ConcurrentHashMap<String, GSMessage> getMessagesReceived() {
		return messagesReceived;
	}

	private final ConcurrentHashMap<String, GSMessage> messagesReceived = new ConcurrentHashMap<>();

	public GSServerAsync(int port) {
		this.port = port;
	}

	/**
	 * @throws IOException
	 */
	@Override
	public void init() throws IOException {
		try {
			AsynchronousServerSocketChannel serverChannel = AsynchronousServerSocketChannel.open();
			serverChannel.bind(new InetSocketAddress(port));
			System.out.println("server started on port " + port);
			serverChannel.accept(null, new CompletionHandler<AsynchronousSocketChannel, Void>() {
				@Override
				public void completed(AsynchronousSocketChannel clientChannel, Void attachment) {
					serverChannel.accept(null, this); // Accept the next connection

					ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
					InetSocketAddress clientAddress = null;
					try {
						clientAddress = (InetSocketAddress) clientChannel.getRemoteAddress();
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
					String clientKey = clientAddress.toString();
					System.out.println("client key : " + clientKey);
					clients.put(clientKey, clientChannel);
					readMessage(clientChannel);
				}

				@Override
				public void failed(Throwable exc, Void attachment) {
					System.out.println("Failed to accept a connection: " + exc.getMessage());
				}
			});
			// Keep the main thread alive
			Thread.currentThread().join();
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
	}

	private void readMessage(AsynchronousSocketChannel clientChannel) {
		ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);
		AsynchronousSocketChannel client = null;
		GSMessage receivedMessage = null;
		try {
			client = clients.get(clientChannel.getRemoteAddress().toString());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		AsynchronousSocketChannel finalClient = client;
		finalClient.read(buffer, buffer, new CompletionHandler<Integer, ByteBuffer>() {
			@Override
			public void completed(Integer bytesRead, ByteBuffer buffer) {
				if (bytesRead == -1) {
					// Client disconnected
					try {
						System.out.println("Client disconnected: " + finalClient.getRemoteAddress());
						clients.remove(finalClient.getRemoteAddress());
//						finalClient.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				} else {
//					buffer.flip();
					GSMessage receivedMessage = null;
					try {
						receivedMessage = GSMessage.deserialize(buffer.array());
						handleMessage(finalClient, receivedMessage);
					} catch (IOException | ClassNotFoundException e) {
						throw new RuntimeException(e);
					}
//					 Prepare the buffer for the next read and trigger another read operation
//					buffer.clear();
//					finalClient.read(buffer, buffer, this);

					sendResponse(finalClient, receivedMessage);
				}
			}

			@Override
			public void failed(Throwable exc, ByteBuffer buffer) {
				System.out.println("Read failed: " + exc.getMessage());
				try {
					finalClient.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		});
	}

	private void sendResponse(AsynchronousSocketChannel clientChannel, GSMessage receivedMessage) {
		// correct code
		try {
			HashMap<URN, Object> messageElements2 = new HashMap<URN, Object>();
			messageElements2.put(URN.createUnsafeZkpgsURN("urn5"), receivedMessage.getType());
			messageElements2.put(URN.createUnsafeZkpgsURN("urn6"), receivedMessage.getType());
			GSMessage message = new GSMessage(receivedMessage.getType(), messageElements2);
//			if (clientChannel.isOpen()) {
				sendMessage(clientChannel, message);
//			} else {
//				System.out.println("client channel is closed");
//				clients.remove(clientChannel.getRemoteAddress().toString());
//				clientChannel.close();
//			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void handleMessage(AsynchronousSocketChannel clientChannel, GSMessage message) throws IOException {
		switch (message.getType()) {
			case CONNECT:
				System.out.println("Client connected: " + message.getPayload());
				break;
			case DISCONNECT:
				System.out.println("Client disconnected: " + message.getPayload());
				clients.remove(clientChannel.getRemoteAddress().toString());
				closeChannel(clientChannel);
				break;
			case DATA:
				System.out.println("handle Received message: " + message.getPayload());
				messagesReceived.put(clientChannel.getRemoteAddress().toString(), message);
//				broadcastMessage(clientChannel, message);
				break;
			case INIT:
				System.out.println("Initialization Received message: " + message.getPayload());
				messagesReceived.put(clientChannel.getRemoteAddress().toString(), message);
				break;
			case REGISTER:
				System.out.println("Registration Received message: " + message.getPayload());
				messagesReceived.put(clientChannel.getRemoteAddress().toString(), message);
				break;
			case CERTIFY:
				System.out.println("Certification Received message: " + message.getPayload());
				messagesReceived.put(clientChannel.getRemoteAddress().toString(), message);
				break;
			case ATTEST:
				System.out.println("Attestation Received message: " + message.getPayload());
				messagesReceived.put(clientChannel.getRemoteAddress().toString(), message);
				break;
			default:
				break;
		}
	}

	//	private void broadcastMessage(AsynchronousSocketChannel sender, GSMessage message) {
//		clients.forEach((clientChannel, buffer) -> {
//			if (clientChannel != sender) {
//				try {
//					sendMessage(clientChannel, message);
//				} catch (IOException e) {
//					throw new RuntimeException(e);
//				}
//			}
//		});
//	}
	private void sendMessage(AsynchronousSocketChannel clientChannel, GSMessage message) throws IOException {
		byte[] bytes = message.serialize();
		ByteBuffer buffer = ByteBuffer.wrap(bytes);
		clientChannel.write(buffer, null, new CompletionHandler<Integer, Void>() {
			@Override
			public void completed(Integer bytesWritten, Void attachment) {
				if (buffer.hasRemaining()) {
					clientChannel.write(buffer, null, this);
				} else {
					try {
						System.out.println("GSMessage sent to : " + clientChannel.getRemoteAddress() + " " + message.getMessageElements());
						readMessage(clientChannel);
					} catch (IOException e) {
						throw new RuntimeException(e);
					}
				}
			}

			@Override
			public void failed(Throwable exc, Void attachment) {
				System.out.println("Failed to send message: " + exc.getMessage());
				try {
					System.out.println("Closing channel" + clientChannel.getLocalAddress());
					clientChannel.close();
				} catch (IOException e) {
					System.out.println(e);
				}
			}
		});
	}

	private void closeChannel(AsynchronousSocketChannel channel) {
		try {
			channel.close();
		} catch (IOException e) {
			System.out.println("Failed to close client channel: " + e.getMessage());
		}
	}

	/**
	 * @throws IOException
	 */
	@Override
	public void close() throws IOException {

	}

	public void receive() {
	}

	public void send(GSMessage message) {
//			try {
//				HashMap<URN, Object> messageElements2 = new HashMap<URN, Object>();
//				messageElements2.put(URN.createUnsafeZkpgsURN("urn5"), clientKey);
//				messageElements2.put(URN.createUnsafeZkpgsURN("urn6"), clientKey);
//				GSMessage message = new GSMessage(GSMessage.MessageType.DATA, messageElements2);
//				if (clientChannel.isOpen()){
//					sendMessage(clientChannel, message);
//				} else {
//					System.out.println("client channel is closed");
//					clients.remove(clientChannel.getRemoteAddress().toString());
//					clientChannel.close();
////							sendMessage(clientChannel, message);
//
//				}
//			} catch (IOException e) {
//				throw new RuntimeException(e);
//			}

	}
}
