package uk.ac.ncl.cascade.zkpgs.verifier;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

public interface IVerifier extends IURNGoverner {
	
	/**
	 * Evaluates the verification computation, producing a verifier-side hat-value.
	 * 
	 * <p>In terms of overall proof-consistency, the hat-value produced by the component
	 * verifier must equal the tilde-value of the corresponding prover. 
	 * 
	 * <p>The method relies upon the public values and responses being stored in the
	 * ProofStore under URNs that correspond to the component verifier.
	 * 
	 * @param cChallenge the challenge of the overall proof.
	 * @return Map with multiple hat-value to be included in the overall verification.
	 * 
	 * @throws ProofStoreException if storing or retrieving elements from the proof store fails
	 * @throws VerificationException if checking lengths fails
	 */
	Map<URN, GroupElement> executeCompoundVerification(BigInteger cChallenge) throws ProofStoreException, VerificationException;
	
	/**
	 * Evaluates the verification computation, producing a verifier-side hat-value.
	 * 
	 * <p>In terms of overall proof-consistency, the hat-value produced by the component
	 * verifier must equal the tilde-value of the corresponding prover. 
	 * 
	 * <p>The method relies upon the public values and responses being stored in the
	 * ProofStore under URNs that correspond to the component verifier.
	 * 
	 * @param cChallenge the challenge of the overall proof.
	 * @return GroupElement hat-value to be included in the overall verification.
	 * 
	 * @throws ProofStoreException if storing or retrieving elements from the proof store fails
	 * @throws VerificationException if checking lengths fails
	 */
	GroupElement executeVerification(BigInteger cChallenge) throws ProofStoreException, VerificationException;
	
	/**
	 * Checks the lengths of inputed prover-responses (hat-values).
	 *  
	 * @return <tt>true</tt> if the lengths fulfil the requirements for the given prover.
	 */
	boolean checkLengths();
	
	/**
	 * Returns a list of the URN identifiers of the data in the ProofStore
	 * that this verifier governs.
	 * 
	 * @return List of URNs this verifier is responsible for.
	 */
	List<URN> getGovernedURNs();
}
