package uk.ac.ncl.cascade.zkpgs.prover;

import uk.ac.ncl.cascade.zkpgs.exception.NotImplementedException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPrivateKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.NumberConstants;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRElement;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Establishes the correctness of the Signer's Strong RSA signature, with Q as pre-signing value.
 */
public class SigningQCorrectnessProver implements IProver {

	public static final String URNID = "issuing.signer";

	//private Logger gslog = GSLoggerConfiguration.getGSlog();

	private final ProofStore<Object> proofStore;
	private final SignerPublicKey signerPublicKey;
	private final SignerPrivateKey signerPrivateKey;
	private final KeyGenParameters keyGenParameters;
	private final GSSignature gsSignature;
	private final BigInteger n_2;
	private BigInteger tilded;
	private BigInteger hatd;
	private BigInteger d;
	private GroupElement Q;

	private GroupElement tildeA;

	private BigInteger cPrime;

	public SigningQCorrectnessProver(
			final GSSignature gsSignature,
			final BigInteger n_2,
			final SignerKeyPair skp,
			final ProofStore<Object> ps) {
		
		Assert.notNull(gsSignature, "The graph signature must not be null.");
		Assert.notNull(n_2, "The nonce n_2 must not be null.");
		Assert.notNull(skp, "The signer keypair must not be null.");
		Assert.notNull(ps, "The ProofStore must not be null.");
		
		this.proofStore = ps;
		this.signerPublicKey = skp.getPublicKey();
		this.signerPrivateKey = skp.getPrivateKey();
		this.gsSignature = gsSignature;
		this.keyGenParameters = skp.getKeyGenParameters();
		this.n_2 = n_2;
	}

	@Override
	public void executePrecomputation() {
		// NO PRE-COMPUTATION IS NEEDED: NO-OP.
	}

	@Override
	public GroupElement executePreChallengePhase() throws ProofStoreException {

		this.Q = (QRElement) proofStore.retrieve("issuing.signer.Q");

		BigInteger order = signerPrivateKey.getPPrime().multiply(signerPrivateKey.getQPrime());

		this.tilded =
				CryptoUtilsFacade.computeRandomNumber(
						NumberConstants.TWO.getValue(), order.subtract(BigInteger.ONE));

		proofStore.store(URNType.buildURNComponent(URNType.TILDED, this.getClass()), tilded);
		tildeA = Q.modPow(tilded);
		
		proofStore.store(URNType.buildURNComponent(URNType.TILDEA, this.getClass()), tildeA);

		return tildeA;
	}

	@Override
	public Map<URN, GroupElement> executeCompoundPreChallengePhase() throws ProofStoreException {
		GroupElement tildeA = executePreChallengePhase();
		Map<URN, GroupElement> witnesses = new HashMap<URN, GroupElement>();
		String tildeAURN = URNType.buildURNComponent(URNType.TILDEA, SigningQCorrectnessProver.class);
		witnesses.put(URN.createZkpgsURN(tildeAURN), tildeA);
		return witnesses;
	}

	@Override
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cPrime)
			throws ProofStoreException {
		Assert.notNull(cPrime, "The challenge must not be null.");
		
		this.cPrime = cPrime;
		
		this.d = (BigInteger) proofStore.retrieve("issuing.signer.d");

		BigInteger order = signerPrivateKey.getPPrime().multiply(signerPrivateKey.getQPrime());
		hatd = (tilded.subtract(cPrime.multiply(d))).mod(order);
		Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>(1);
		responses.put(
				URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, this.getClass())), hatd);
		return responses;
	}

	@Override
	public boolean verify() {
		if (this.cPrime == null || this.tildeA == null || this.hatd == null) return false;
		
		BigInteger verificationExp = cPrime.add(hatd.multiply(gsSignature.getE()));
		
		GroupElement hatA = gsSignature.getA().modPow(verificationExp);
		
		return hatA.equals(tildeA);
	}

	@Override
	public List<URN> getGovernedURNs() {
		throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
	}
}
