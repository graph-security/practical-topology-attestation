package uk.ac.ncl.cascade.verifier;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.graph.GraphRepresentation;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.PossessionProver;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigningOracle;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.*;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import uk.ac.ncl.cascade.zkpgs.verifier.PossessionVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.*;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GraphPossessionVerifierTest {

	private Logger log = GSLoggerConfiguration.getGSlog();
	private SignerKeyPair signerKeyPair;
	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private ExtendedKeyPair extendedKeyPair;
	private ProofStore<Object> proverProofStore;
	private ProofStore<Object> verifierProofStore;
	private PossessionVerifier verifier;
	private PossessionProver prover;
	private GSSigningOracle oracle;
	private ExtendedPublicKey epk;
	private BigInteger testM;
	private GSSignature sigmaG;
	private BaseCollection baseCollection;
	private BigInteger cChallenge;
	private BigInteger hate;
	private BigInteger hatvPrime;
	private BigInteger hatm_0;
	private GroupElement tildeZ;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();
		epk = extendedKeyPair.getExtendedPublicKey();

		oracle = new GSSigningOracle(signerKeyPair, keyGenParameters);
	}

	@BeforeEach
	void setUp() throws Exception {
		proverProofStore = new ProofStore<Object>();
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		assertNotNull(testM, "Test message, a random number, could not be generated.");

		log.info("Creating test signature with GSSigningOracle on testM: " + testM);
		GraphRepresentation gr = GraphUtils.createGraph(DefaultValues.SIGNER_GRAPH_FILE, testM, epk);
		baseCollection = gr.getEncodedBaseCollection();

		proverProofStore.store("bases.exponent.m_0", testM);

		assertNotNull(baseCollection);
		assertTrue(baseCollection.size() > 0);
		log.info("Size of the base collection: " + baseCollection.size());

		Iterator<BaseRepresentation> basesVertices =
				baseCollection.createIterator(BASE.VERTEX).iterator();
		log.info("||Sigma Vertex Bases: " + GraphUtils.iteratedGraphToString(basesVertices));

		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);
		while (vertexIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) vertexIter.next();
			log.log(
					Level.INFO,
					"BaseRepresentation[ "
							+ base.getBaseIndex()
							+ ", "
							+ base.getBaseType()
							+ "]:\n   Base: "
							+ base.getBase()
							+ "\n   Exponent: "
							+ base.getExponent());
			assertNotNull(base);
			assertNotNull(base.getBase(), "Base with index " + base.getBaseIndex() + " was null.");
		}

		Iterator<BaseRepresentation> basesEdges = baseCollection.createIterator(BASE.EDGE).iterator();
		log.info("||Sigma Edge Bases:    " + GraphUtils.iteratedGraphToString(basesEdges));

		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		while (edgeIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) edgeIter.next();
			log.log(
					Level.INFO,
					"BaseRepresentation[ "
							+ base.getBaseIndex()
							+ ", "
							+ base.getBaseType()
							+ "]:\n   Base: "
							+ base.getBase()
							+ "\n   Exponent: "
							+ base.getExponent());
			assertNotNull(base);
			assertNotNull(base.getBase(), "Base with index " + base.getBaseIndex() + " was null.");
		}

		log.info("Attempting to sign base collection.");
		sigmaG = oracle.sign(baseCollection);
		assertNotNull(sigmaG.getEncodedBases(), "Encoded bases were left null after testcase setup.");

		sigmaG = sigmaG.blind();
		assertNotNull(sigmaG.getEncodedBases(), "Encoded bases were null after blinding in testcase setup.");

		storeBlindedGS(sigmaG);


		log.info("Computing a PossessionProof to be verified.");
		prover = new PossessionProver(sigmaG, epk, proverProofStore);

		tildeZ = prover.executePreChallengePhase();

		cChallenge = prover.computeChallenge();
		prover.executePostChallengePhase(cChallenge);


		// Setting up verifier proof store
		verifierProofStore = new ProofStore<Object>();
		storeVerifierView(sigmaG.getA());

		// Setting up a separate base collection for the verifier side, exponents purged.

		BaseCollection verifierBaseCollection = baseCollection.clone();
		verifierBaseCollection.removeExponents();
		log.info("||Verifier collection: "
				+ GraphUtils.iteratedGraphToExpString(verifierBaseCollection.createIterator(BASE.ALL).iterator(),
				verifierProofStore));

		verifier = new PossessionVerifier(verifierBaseCollection, epk, verifierProofStore);
	}

	/**
	 * The test checks whether the PossessionVerifier computes hatZ correctly.
	 */
	@Test
	void testComputeHatZ() throws Exception {
		log.info("Checking the verifier's computation of hatZ");
		GroupElement hatZ = verifier.executeVerification(cChallenge);

		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(hatZ));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(tildeZ));

		assertEquals(
				tildeZ,
				hatZ,
				"The hatZ computed by the verifier is not equal to the prover's witness tildeZ.");
	}

	/**
	 * The test checks whether the PossessionVerifier correctly aborts when inputs (hat-values) with
	 * wrong lengths are used. The critical case is that the lengths may be longer than asked for.
	 */
	@Test
	void testIllegalLengths() throws Exception {
		// Compute hat-values that are too long and store them in the ProofStore.
		log.info("Replacing correct hat-values with oversized ones.");
		hate = hate.multiply(BigInteger.TEN);
		hatvPrime = hatvPrime.multiply(BigInteger.TEN);
		hatm_0 = hatm_0.multiply(BigInteger.TEN);

		verifierProofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.responses.hate"));
		verifierProofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.responses.hatvPrime"));
		verifierProofStore.remove(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "verifier.responses.hatm_0"));
		verifierProofStore.store("verifier.responses.hate", hate);
		verifierProofStore.store("verifier.responses.hatvPrime", hatvPrime);
		verifierProofStore.store("verifier.responses.hatm_0", hatm_0);

		log.info("Testing whether the verifier correctly aborts on over-sized hat-values");
		GroupElement hatZ = verifier.executeVerification(cChallenge);

		assertNull(
				hatZ,
				"The PossionVerifier should have aborted outputting null "
						+ "upon receiving ill-sized inputs, but produced a non-null output.");
	}

	private void storeBlindedGS(GSSignature sigma) throws Exception {
		String blindedGSURN = "prover.blindedgs.signature.sigma";
		proverProofStore.store(blindedGSURN, sigma);

		String APrimeURN = "prover.blindedgs.signature.APrime";
		proverProofStore.store(APrimeURN, sigma.getA());

		String ePrimeURN = "prover.blindedgs.signature.ePrime";
		proverProofStore.store(ePrimeURN, sigma.getEPrime());

		String vPrimeURN = "prover.blindedgs.signature.vPrime";
		proverProofStore.store(vPrimeURN, sigma.getV());
	}

	private void storeVerifierView(GroupElement aPrime) throws Exception {
		log.info("Retrieving hat-values");
		hate = (BigInteger) proverProofStore.retrieve(prover.getProverURN(URNType.HATE));
		hatvPrime = (BigInteger) proverProofStore.retrieve(prover.getProverURN(URNType.HATVPRIME));
		hatm_0 = (BigInteger) proverProofStore.retrieve(prover.getProverURN(URNType.HATM0));
		verifierProofStore.store("verifier.responses.hate", hate);
		verifierProofStore.store("verifier.responses.hatvPrime", hatvPrime);
		verifierProofStore.store("verifier.responses.hatm_0", hatm_0);

		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);
		while (vertexIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) vertexIter.next();

			BigInteger hatm = (BigInteger) proverProofStore.retrieve(prover.getProverURN(URNType.HATMI, base.getBaseIndex()));
			Assert.notNull(hatm, "ProofStore did not contain expected prover hat-value: " + base.getBaseIndex());

			verifierProofStore.store(URNType.buildURNComponent(URNType.HATMI, PossessionProver.class, base.getBaseIndex()), hatm);
		}

		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		while (edgeIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) edgeIter.next();
			BigInteger hatm = (BigInteger) proverProofStore.retrieve(prover.getProverURN(URNType.HATMIJ, base.getBaseIndex()));
			Assert.notNull(hatm, "ProofStore did not contain expected prover hat-value: " + base.getBaseIndex());

			verifierProofStore.store(URNType.buildURNComponent(URNType.HATMIJ, PossessionProver.class, base.getBaseIndex()), hatm);
		}

		verifierProofStore.store("verifier.c", cChallenge);
		verifierProofStore.store("verifier.APrime", aPrime);
	}

	@Test
	void testInformationFlow() {
		BaseIterator bases = baseCollection.createIterator(BASE.ALL);
		for (BaseRepresentation base : bases) {
			assertFalse(InfoFlowUtil.doesBaseGroupElementLeakPrivateInfo(base));
		}

		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(sigmaG.getA()));
	}
}
