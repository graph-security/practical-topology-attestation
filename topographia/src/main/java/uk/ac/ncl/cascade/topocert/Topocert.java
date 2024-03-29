package uk.ac.ncl.cascade.topocert;

import  uk.ac.ncl.cascade.zkpgs.DefaultValues;
import  uk.ac.ncl.cascade.zkpgs.exception.*;
import  uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import  uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import  uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import  uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import  uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import  uk.ac.ncl.cascade.zkpgs.orchestrator.ProverOrchestrator;
import  uk.ac.ncl.cascade.zkpgs.orchestrator.RecipientOrchestrator;
import  uk.ac.ncl.cascade.zkpgs.orchestrator.SignerOrchestrator;
import  uk.ac.ncl.cascade.zkpgs.orchestrator.VerifierOrchestrator;
import  uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import  uk.ac.ncl.cascade.zkpgs.parameters.JSONParameters;
import  uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import  uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import jargs.gnu.CmdLineParser;
import org.jgrapht.io.ImportException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Vector;

import static  uk.ac.ncl.cascade.zkpgs.DefaultValues.CLIENT;
import static  uk.ac.ncl.cascade.zkpgs.DefaultValues.SERVER;


public class Topocert {

	private KeyGenParameters keyGenParams;
	private GraphEncodingParameters graphEncParams;
	private FilePersistenceUtil persistenceUtil;
	private ExtendedPublicKey epk;

	private static boolean verbose = false;

	public Topocert() {

	}

	public static void main(String[] argv) {
		TopocertCmdLineParser parser = new TopocertCmdLineParser();

		try {
			parser.parse(argv);
		} catch (CmdLineParser.UnknownOptionException e) {
			System.err.println(e.getMessage() + "\n");
			parser.printUsage();
			System.exit(TopocertErrorCodes.EX_USAGE);
		} catch (CmdLineParser.IllegalOptionValueException e) {
			System.err.println(e.getMessage() + "\n");
			parser.printUsage();
			System.exit(TopocertErrorCodes.EX_USAGE);
		}

		// Boolean Options
		Boolean keygenMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.KEYGEN);
		Boolean signMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.SIGN);
		Boolean receiveMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.RECEIVE);
		Boolean proveMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.PROVE);
		Boolean verifyMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.VERIFY);

		Boolean verboseLogs = (Boolean) parser.getOptionValue(TopocertCmdLineParser.VERBOSE);

		Boolean offerHelp = (Boolean) parser.getOptionValue(TopocertCmdLineParser.HELP);

		// String Options
		String graphFilename = (String) parser.getOptionValue(TopocertCmdLineParser.GRAPHFILENAME, TopocertDefaultOptionValues.DEF_GRAPH);
		String paramsFilename = (String) parser.getOptionValue(TopocertCmdLineParser.KEYGENPARAMS, TopocertDefaultOptionValues.DEF_KEYGEN_PARAMS);
		// String encodingFilename = TopocertDefaultOptionValues.DEF_COUNTRY_ENCODING;

		String signerKeyFilename = (String) parser.getOptionValue(TopocertCmdLineParser.SIGNERKP, TopocertDefaultOptionValues.DEF_SKP);
		String signerPKFilename = (String) parser.getOptionValue(TopocertCmdLineParser.SIGNERKP, TopocertDefaultOptionValues.DEF_PK);
		String ekpFilename = TopocertDefaultOptionValues.DEF_EKP;
		String epkFilename = (String) parser.getOptionValue(TopocertCmdLineParser.EPK, TopocertDefaultOptionValues.DEF_EPK);
		String sigmaFilename = (String) parser.getOptionValue(TopocertCmdLineParser.GSSIGNATURE, TopocertDefaultOptionValues.DEF_GSSIGNATURE);
		String hostAddress = (String) parser.getOptionValue(TopocertCmdLineParser.HOST_ADDRESS, TopocertDefaultOptionValues.DEF_HOST_ADDRESS);
		

		// Integer Options: Zero or Multiple Queries
		@SuppressWarnings("unchecked")
		Vector<Integer> queryValues = (Vector<Integer>) parser.getOptionValues(TopocertCmdLineParser.GEOSEPQUERY);
		Integer portNumber = (Integer) parser.getOptionValue(TopocertCmdLineParser.PORT_NUMBER, TopocertDefaultOptionValues.DEF_PORT_NUMBER);
		// User needing help?
		if (offerHelp != null && offerHelp.booleanValue()) {
			parser.printUsage();
			System.exit(0);
		}

		if (verboseLogs != null && verboseLogs.booleanValue()) {
			Topocert.verbose = true;
		}

		// Checking that there is exactly one mode specified.
		int numberOfModes = 0;
		if (keygenMode != null && keygenMode.booleanValue()) numberOfModes++;
		if (signMode != null && signMode.booleanValue()) numberOfModes++;
		if (receiveMode != null && receiveMode.booleanValue()) numberOfModes++;
		if (proveMode != null && proveMode.booleanValue()) numberOfModes++;
		if (verifyMode != null && verifyMode.booleanValue()) numberOfModes++;
		if (numberOfModes == 0 || numberOfModes > 1) {
			System.err.println("Please specify exactly one mode for TOPOCERT to run in.\n");
			parser.printUsage();
			System.exit(TopocertErrorCodes.EX_USAGE);
		}

		// Initialize Topocert and Read Parameters
		Topocert topocert = new Topocert();
		topocert.readParams(paramsFilename);

		//
		// Main Behavior Branching
		//
		try {
			if (keygenMode != null && keygenMode.booleanValue()) {
				// Initialize TOPOCERT keygen
				System.out.println("Entering TOPOCERT key generation...");
				System.out.println("  Designated signer keypair file: " + signerKeyFilename);
				System.out.println("  Designated extended public key file: " + epkFilename);

				try {
					topocert.keygen(signerKeyFilename, ekpFilename, signerPKFilename, epkFilename);
				} catch (IOException e) {
					handleException(e, "The TOPOCERT keys could not be written to file.",
							TopocertErrorCodes.EX_IOERR);
				} catch (EncodingException e) {
					handleException(e, "The TOPOCERT graph encoding could not be setup.",
							TopocertErrorCodes.EX_ENCERR);
				}

				System.exit(0);
			} else if (signMode != null && signMode.booleanValue()) {
				// Initialize signing, with specified signer graph file.
				System.out.println("Entering TOPOCERT Sign mode...");
				System.out.println("  Using extended keypair from file: " + ekpFilename);

				ExtendedKeyPair ekp = null;
				System.out.print("  Establishing extended signer keypair...");
				try {
					ekp = topocert.readExtendedKeyPair(ekpFilename);
				} catch (IOException e) {
					handleException(e, "The TOPOCERT extended signer key pair could not be read.",
							TopocertErrorCodes.EX_CRITFILE);
				} catch (ClassNotFoundException e) {
					handleException(e, "The TOPOCERT extended signer key pair does not correspond the current class.",
							TopocertErrorCodes.EX_CRITERR);
				}
				if (ekp == null) {
					System.err.println("Extended signer keypair could not be established; returned null.");
					System.exit(TopocertErrorCodes.EX_SOFTWARE);
				}
				System.out.println("   [done]\n");

				topocert.sign(ekp, graphFilename, hostAddress, portNumber);

				System.exit(0);
			} else if (receiveMode != null && receiveMode.booleanValue()) {
				// Initialize receiving of a signature.
				System.out.println("Entering TOPOCERT Receive mode...");
				System.out.println("  Using Signer's extended public key: " + epkFilename);

				topocert.readEPK(epkFilename);

				topocert.receive(graphFilename, sigmaFilename, hostAddress, portNumber);

				System.exit(0);
			} else if (proveMode != null && proveMode.booleanValue()) {
				// Initialize proving
				System.out.println("Entering TOPOCERT Prove mode...");
				System.out.println("  Using Signer's extended public key: " + epkFilename);

				topocert.readEPK(epkFilename);

				topocert.prove(graphFilename, sigmaFilename, hostAddress, portNumber);

				System.exit(0);
			} else if (verifyMode != null && verifyMode.booleanValue()) {
				// Initialize verifying, specifying queries
				if (queryValues == null || queryValues.isEmpty() || queryValues.size() < 2) {
					System.err.println("In Verify mode, please name at least two vertices with the -q/--query option.\n");
					parser.printUsage();
					System.exit(TopocertErrorCodes.EX_USAGE);
				}
				System.out.println("Entering TOPOCERT Verify mode...");
				System.out.println("  Using Signer's extended public key: " + epkFilename);
				System.out.print("  Queried vertices: [ ");
				for (Iterator<Integer> iterator = queryValues.iterator(); iterator.hasNext(); ) {
					Integer queriedVertex = (Integer) iterator.next();
					System.out.print(queriedVertex);
					if (iterator.hasNext()) System.out.print(", ");
				}
				System.out.println(" ].");

				topocert.readEPK(epkFilename);

				topocert.verify(queryValues, hostAddress, portNumber);

				System.exit(0);
			} else {
				System.err.println("Please specify a mode to operate in.\n");
				parser.printUsage();
				System.exit(TopocertErrorCodes.EX_USAGE);
			}

			// Severe Error Conditions
		} catch (IllegalStateException e) {
			handleException(e, "TOPOCERT detected an illegal state and is aborting "
					+ "the protocol run.", TopocertErrorCodes.EX_STATE);
		} catch (IllegalArgumentException e) {
			handleException(e, "TOPOCERT detected a call with an illegal argument "
					+ "and is aborting the protocol run.", TopocertErrorCodes.EX_SOFTWARE);
		} catch (NotImplementedException e) {
			handleException(e, "TOPOCERT detected that a method was called that has "
					+ "not been released for production yet.", TopocertErrorCodes.EX_SOFTWARE);
		} catch (RuntimeException e) {
			handleException(e, "TOPOCERT detected a runtime exception "
					+ "and is aborting the protocol run.", TopocertErrorCodes.EX_SOFTWARE);
		} catch (GSInternalError e) {
			handleException(e, "TOPOCERT detected an unexpcected, critical internal error "
					+ "that it could not recover from.", TopocertErrorCodes.EX_CRITERR);
		}

		System.exit(0);
	}


	void readParams(String paramsFilename) {
		System.out.print("Reading parameters from file: " + paramsFilename + "...");
		try {
			readKeyGenParams(paramsFilename);
		} catch (Exception e) {
			handleException(e, "The TOPOCERT keygen and graph encoding "
					+ "parameters could not be parsed from file: " + paramsFilename + ".",
					TopocertErrorCodes.EX_CONFIG);
		}
		System.out.println("   [done]");
		System.out.println("  Setup for key bitlength: " + getKeyGenParams().getL_n() + "\n");
	}

	void readKeyGenParams(String paramsFilename) {
		JSONParameters parameters = new JSONParameters(paramsFilename);
		keyGenParams = parameters.getKeyGenParameters();
		graphEncParams = parameters.getGraphEncodingParameters();
		persistenceUtil = new FilePersistenceUtil();
		//		String defSignerKeyFile = "SignerKeyPair-" + keyGenParams.getL_n() + ".ser";
		//		String defEpkFile = "ExtendedPublicKey-" + keyGenParams.getL_n() + ".ser";
	}

	SignerKeyPair readSignerKeyPair(String signerKeyPairFilename) throws
	IOException, ClassNotFoundException {

		SignerKeyPair signerKeyPair = (SignerKeyPair) persistenceUtil.read(signerKeyPairFilename);

		return signerKeyPair;
	}

	ExtendedKeyPair readExtendedKeyPair(String extendedKeyPairFilename) throws
	IOException, ClassNotFoundException {


		ExtendedKeyPair extendedKeyPair = (ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFilename);

		return extendedKeyPair;
	}

	ExtendedPublicKey readExtendedPublicKey(String epkFilename) throws
	IOException, ClassNotFoundException {

		this.epk =
				(ExtendedPublicKey) persistenceUtil.read(epkFilename);

		return epk;
	}

	void readEPK(String epkFilename) {
		System.out.print("  Reading extended public key...");
		try {
			readExtendedPublicKey(epkFilename);
		} catch (IOException e) {
			handleException(e, "The TOPOCERT extended public keu could not be read.",
					TopocertErrorCodes.EX_CRITFILE);
		} catch (ClassNotFoundException e) {
			handleException(e, "The TOPOCERT extended public key does not correspond the current class.",
					TopocertErrorCodes.EX_CRITERR);
		}
		System.out.println("   [done]\n");
		System.out.println("  Extended Public Key holds " + epk.getBases().size() + " graph encoding bases.");
	}


	void keygen(String signerKeyPairFilename, String ekpFilename, String signerPKFilename, String epkFilename) throws IOException, EncodingException {
		// Establishing Signer Key Pair First
		SignerKeyPair gsk = new SignerKeyPair();
		System.out.print("  Keygen - Stage I:   Generating SRSA Signer key pair.");
		gsk.keyGen(keyGenParams);
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage I:   Writing new Signer KeyPair...");
		persistenceUtil.write(gsk, signerKeyPairFilename);
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage I:   Writing new Signer PublicKey...");
		persistenceUtil.write(gsk.getPublicKey(), signerPKFilename);
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage II:  Generating bases for encoding...");
		ExtendedKeyPair ekp = new ExtendedKeyPair(gsk, graphEncParams, keyGenParams);
		ekp.generateBases();
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage II:  Setting up geo-location encoding...");
		ekp.setupEncoding();
		System.out.println("   [done]");

		System.out.print("  Keygen - Stage III: Finalizing extended keypair...");
		ekp.createExtendedKeyPair();
		System.out.println("   [done]");

		System.out.print("  Keygen: - Stage III: Writing new ExtendedKeyPair...");
		persistenceUtil.write(ekp, ekpFilename);
		System.out.println("   [done]");

		System.out.print("  Keygen: - Stage III: Writing new ExtendedPublicKey...");
		this.epk = ekp.getExtendedPublicKey();
		persistenceUtil.write(ekp.getExtendedPublicKey(), epkFilename);
		System.out.println("   [done]");

		System.out.println("  Keygen: Completed.");
	}


	void sign(ExtendedKeyPair ekp, String graphFilename, String hostAddress, int portNumber) {
		System.out.println("  Sign: Acts as client for interactive signing of graph: " + graphFilename + ".");
		IMessageGateway messageGateway = new MessageGatewayProxy(CLIENT, hostAddress, portNumber);
		SignerOrchestrator signer = new SignerOrchestrator(graphFilename, ekp, messageGateway);

		System.out.print("  Sign: Initializing the Signer role...");
		try {
			signer.init();
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Signer could not establish a connection to the Recipient in Round 0.",
					TopocertErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Sign - Round 0: Starting round0: Sending nonce...");
		try {
			signer.round0();
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Signer could not send the nonce to the Recipient in Round 0.",
					TopocertErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		
		System.out.println();


		System.out.print("  Sign - Round 2: Waiting for the Recipient's commitment...");
		try {
			signer.round2();
		} catch (NoSuchAlgorithmException e) {
			handleException(e, "The TOPOCERT Signer could not compute the Fiat-Shamir "
					+ "hash in Round 2 due to missing hash algorithm.",
					TopocertErrorCodes.EX_CRITERR);
		} catch (ImportException e) {
			handleException(e, "The TOPOCERT Signer not import the GraphML file in Round 2.",
					TopocertErrorCodes.EX_NOINPUT);
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Signer could not read the GraphML file in Round 2.",
					TopocertErrorCodes.EX_IOERR);
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOCERT Signer not store/retrieve elements in the ProofStore in Round 2.",
					TopocertErrorCodes.EX_DATAERR);
		} catch (VerificationException e) {
			handleException(e, "The TOPOCERT Signer could not verify the proof of representation of "
					+ "the Recipient's commitment in Round 2.",
					TopocertErrorCodes.EX_VERIFY);
		} catch (EncodingException e) {
			handleException(e, "The TOPOCERT Signer could not encode the graph in Round 2.",
					TopocertErrorCodes.EX_ENCERR);
		}
		System.out.println("   [done]");
		
		System.out.println("  Sign - Round 2: Commitment and proof of representation verified.");
		System.out.println("  Sign - Round 2: Pre-Signature and proof of representation sent.");


		try {
			signer.close();
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Signer failed to close the connection to the Recipient soundly.",
					TopocertErrorCodes.EX_IOERR);
		}

		System.out.println("  Sign: Completed");
	}

	void receive(String graphFilename, String sigmaFilename, String hostAddress, int portNumber) {
		System.out.println("  Receive: Acts as host to receive a new graph signature.");
		IMessageGateway messageGateway = new MessageGatewayProxy(SERVER, hostAddress, portNumber);
		RecipientOrchestrator recipient = new RecipientOrchestrator(graphFilename, epk, messageGateway);

		System.out.print("  Receive: Initializing the Recipient role...");
		try {
			recipient.init();
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Recipient could not open a server socket for the Signer in Round 0.",
					TopocertErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Receive - Round 1: Waiting the Signer's nonce...");
		try {
			recipient.round1();
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOCERT Recipient could not complete its commitment in Round 1.",
					TopocertErrorCodes.EX_CRITERR);
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Recipient could not receive the nonce from the Signer in Round 1.",
					TopocertErrorCodes.EX_NOHOST);
		} catch (NoSuchAlgorithmException e) {
			handleException(e, "The TOPOCERT Recipient could not compute the Fiat-Shamir "
					+ "hash in Round 2 due to missing hash algorithm.",
					TopocertErrorCodes.EX_CRITERR);
		}
		System.out.println("   [done]");
		
		System.out.println();

		System.out.print("  Receive - Round 3: Waiting for the Signer's pre-signature...");
		try {
			recipient.round3();
		} catch (VerificationException e) {
			handleException(e, "The TOPOCERT Recipient could not verify the Signer's proof on the "
					+ "presented new signature in Round 3.",
					TopocertErrorCodes.EX_VERIFY);
		} catch (ProofStoreException e) {
			handleException(e, "The TOPOCERT Recipient could not access expected "
					+ "data in the ProofStore in Round 3.",
					TopocertErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "There was an IO Exception while the TOPOCERT Recipient "
					+ "sought to receive the signature from the Signer in Round 3.",
					TopocertErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println("  Receive - Round 3: Received pre-signature from Signer.");
		System.out.println("  Receive - Round 3: Representation proof on pre-signature verified.");
		System.out.println("  Receive - Round 3: Signature completed; internal consistency checked.");


		try {
			recipient.close();
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Recipient could not receive the signature from the Signer in Round 3.",
					TopocertErrorCodes.EX_NOHOST);
		}
		
		System.out.println();

		System.out.print("  Receive: Storing the received graph signature: " 
				+ sigmaFilename + "...");
		try {
			recipient.serializeFinalSignature(sigmaFilename);
		} catch (NullPointerException e) {
			handleException(e, "The graph signature of the Recipient was not "
					+ "correctly assembled; returned null.",
					TopocertErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "The Recipient could not write the obtained graph signature to disk.",
					TopocertErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");

		System.out.println("  Receive: Completed");
	}

	void prove( String graphFilename, String sigmaFilename,String hostAddress, Integer portNumber) {
		System.out.println("  Prove: Acts as host prover for certified graph " + graphFilename + ".");

		IMessageGateway messageGateway = new MessageGatewayProxy(SERVER, hostAddress, portNumber);
		ProverOrchestrator prover = new ProverOrchestrator(epk, messageGateway);

		System.out.print("  Prove: Reading the graph signature from file: "
				+ sigmaFilename + "...");
		try {
			prover.readSignature(sigmaFilename);
		} catch (NullPointerException e) {
			handleException(e, "The Prover's graph signature was null.",
					TopocertErrorCodes.EX_DATAERR);
		} catch (ClassNotFoundException e) {
			handleException(e, "The signature file did not match the GSSignature class.",
					TopocertErrorCodes.EX_CRITFILE);
		} catch (IOException e) {
			handleException(e, "The Prover could not read the graph signature from disk.",
					TopocertErrorCodes.EX_CANTCREAT);
		}
		System.out.println("   [done]");


		System.out.print("  Prove: Initializing the Prover role...");
		try {
			prover.init();
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Prover could not open a socket to receive "
					+ "messages from the Verifier.",
					TopocertErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.print("  Prove: 1. Provers establishing signature proof witnesses...");
		prover.executePreChallengePhase();
		System.out.println("   [done]");

		System.out.print("  Prove: 2. Prover Orchestrator computing overall challenge...");
		BigInteger cChallenge = prover.computeChallenge();
		System.out.println("   [done]");

		System.out.print("  Prove: 3. Provers computing signature proof responses...");
		try {
			prover.executePostChallengePhase(cChallenge);
		} catch (IOException e) {
			handleException(e, "The Prover not send the proof to the Verifier.",
					TopocertErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");
		System.out.println("  Prove: Signature proof of knowledge sent to Verifier.");

		System.out.println("  Prove: Completed");
	}

	void verify(Vector<Integer> vertexQueries,  String hostAddress, Integer portNumber) {
		System.out.println("  Verify: Acts as client for geo-location verification.");
		IMessageGateway messageGateway = new MessageGatewayProxy(CLIENT, hostAddress, portNumber);
		VerifierOrchestrator verifier = new VerifierOrchestrator(epk, messageGateway);

		System.out.print("  Verify: Creating geo-location query predicate...");
		verifier.createQuery(vertexQueries);
		System.out.println("   [done]");

		System.out.print("  Verify: Initializing the Verifier role...");
		try {
			verifier.init();
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Verifier could not open a connection to the Prover.",
					TopocertErrorCodes.EX_NOHOST);
		}
		System.out.println("   [done]");
		System.out.println();

		System.out.println("  Verify: 1. Sent Prover to prover, awaiting signature proof...");
		try {
			verifier.receiveProverMessage();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOCERT Prover could not be verified. "
					+ "Illegal message lengths.",
					TopocertErrorCodes.EX_VERIFY);
		} catch (ProofException e) {
			handleException(e, "The TOPOCERT Prover reported that it cannot complete the proof.",
					TopocertErrorCodes.EX_DATAERR);
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Verifier not receive the proof from the Prover.",
					TopocertErrorCodes.EX_IOERR);
		}
		System.out.println("   [done]");

		System.out.print("  Verify: 2. Computing verification for geo-location verification...");
		try {
			verifier.executeVerification();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOCERT Prover could not be verified. ",
					TopocertErrorCodes.EX_VERIFY);
		}

		verifier.computeChallenge();

		try {
			verifier.verifyChallenge();
		} catch (VerificationException e) {
			handleException(e, "The proof provided by the TOPOCERT Prover could not be verified. ",
					TopocertErrorCodes.EX_VERIFY);
		}
		System.out.println("   [done]");

		System.out.print("  Verify: Signature proof ACCEPTED: Geo-location separation fulfilled for ");
		System.out.print("[ ");
		for (Iterator<Integer> iterator = vertexQueries.iterator(); iterator.hasNext(); ) {
			Integer queriedVertex = (Integer) iterator.next();
			System.out.print(queriedVertex);
			if (iterator.hasNext()) System.out.print(", ");
		}
		System.out.println(" ].");


		try {
			verifier.close();
		} catch (IOException e) {
			handleException(e, "The TOPOCERT Verifier not receive the proof from the Prover.",
					TopocertErrorCodes.EX_IOERR);
		}

		System.out.println("  Verify: Completed");
	}

	private static void handleException(Throwable e, String highLevelMsg, int exitCode) {
		System.err.println("\n\nTOPOCERT Exception:\n" + highLevelMsg);
		if (e.getMessage() != null) System.err.println("\nException message: " + e.getMessage() + "\n");

		if (Topocert.verbose) {
			System.err.println("\nCause of the Exception:\n" + e);

			System.err.println("\nPrinting the stack trace:");
			e.printStackTrace();
		}
		System.err.println("\nTOPOCERT aborting.");

		System.exit(exitCode);
	}


	public KeyGenParameters getKeyGenParams() {
		return this.keyGenParams;
	}
}
