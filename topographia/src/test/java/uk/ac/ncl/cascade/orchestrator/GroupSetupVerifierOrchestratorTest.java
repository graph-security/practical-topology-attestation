package uk.ac.ncl.cascade.orchestrator;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.orchestrator.GroupSetupProverOrchestrator;
import uk.ac.ncl.cascade.zkpgs.orchestrator.GroupSetupVerifierOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;

import java.io.IOException;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GroupSetupVerifierOrchestratorTest {
	
  private SignerKeyPair gsk;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private GroupSetupProverOrchestrator gsProverOrchestrator;
  private ExtendedPublicKey extendedPublicKey;
  private GroupSetupVerifierOrchestrator gsVerifierOrchestrator;
  private ProofSignature proofSignature;
  private SignerPublicKey signerPublicKey;
  private BaseCollection baseCollection;
  private BigInteger cChallenge;
  private BigInteger hatC;

  @BeforeAll
  void setupKey()
      throws IOException, ClassNotFoundException, EncodingException, ProofStoreException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
    signerPublicKey = extendedPublicKey.getPublicKey();
    baseCollection = extendedPublicKey.getBaseCollection();
  }

  @BeforeEach
  void setup() throws ProofStoreException {
    proofStore = new ProofStore<Object>();
    proofSignature = createTestProofSignature();
    gsVerifierOrchestrator =
        new GroupSetupVerifierOrchestrator(proofSignature, extendedPublicKey, proofStore);
  }

  @Test
  @DisplayName("Test verification for the GroupSetupVerifier")
  void executeVerification() throws ProofStoreException {
    boolean isLengthCorrect = gsVerifierOrchestrator.checkLengths();
    assertTrue(isLengthCorrect);
    boolean isVerified = gsVerifierOrchestrator.executeVerification(cChallenge);
    assertTrue(isVerified);
  }

  @Test
  @DisplayName("Test computing hat challenge during verification")
  void computeChallenge() throws ProofStoreException {
    boolean isVerified = gsVerifierOrchestrator.executeVerification(cChallenge);
    hatC = gsVerifierOrchestrator.computeChallenge();
    assertNotNull(hatC);
    assertEquals(cChallenge, hatC, "challenges do not match during verfication");
  }

  @Test
  @DisplayName("Test check lengths")
  void checkLengths() {
    boolean isLengthCorrect = gsVerifierOrchestrator.checkLengths();
    assertNotNull(isLengthCorrect);
    assertTrue(isLengthCorrect);
  }

  @Test
  @DisplayName("Test illegal lengths for the GroupSetupVerifierOrchestrator")
  void testIllegalLengths() throws ProofStoreException {

    String hatrURN = "proofsignature.P.responses.hatr";
    BigInteger hatr =
        (BigInteger) proofSignature.getProofSignatureElements().get(URN.createZkpgsURN(hatrURN));
    assertNotNull(hatr);
    hatr = (BigInteger) hatr.multiply(BigInteger.TEN);

    String hatr_ZURN = "proofsignature.P.responses.hatr_Z";
    BigInteger hatr_Z =
        (BigInteger) proofSignature.getProofSignatureElements().get(URN.createZkpgsURN(hatr_ZURN));
    assertNotNull(hatr_Z);
    hatr_Z = (BigInteger) hatr_Z.multiply(BigInteger.TEN);

    String hatr_0URN = "proofsignature.P.responses.hatr_0";
    BigInteger hatr_0 =
        (BigInteger) proofSignature.getProofSignatureElements().get(URN.createZkpgsURN(hatr_0URN));
    assertNotNull(hatr_0);
    hatr_0 = (BigInteger) hatr_0.multiply(BigInteger.TEN);

    // replace hat values in proof signature with values that have illegal length
    proofSignature.getProofSignatureElements().replace(URN.createZkpgsURN(hatrURN), hatr);

    proofSignature.getProofSignatureElements().replace(URN.createZkpgsURN(hatrURN), hatr_Z);

    proofSignature.getProofSignatureElements().replace(URN.createZkpgsURN(hatrURN), hatr_0);

    GroupSetupVerifierOrchestrator localVerifierOrchestrator =
        new GroupSetupVerifierOrchestrator(proofSignature, extendedPublicKey, proofStore);

    boolean isLengthCorrect = localVerifierOrchestrator.checkLengths();
    assertFalse(isLengthCorrect, "checkLengths method should return false");
  }

  private ProofSignature createTestProofSignature() throws ProofStoreException {

    GroupSetupProverOrchestrator groupSetupProverOrchestrator =
        new GroupSetupProverOrchestrator(extendedKeyPair, proofStore);

    groupSetupProverOrchestrator.executePreChallengePhase();
    cChallenge = groupSetupProverOrchestrator.computeChallenge();
    groupSetupProverOrchestrator.executePostChallengePhase(cChallenge);
    groupSetupProverOrchestrator.createProofSignature();

    return groupSetupProverOrchestrator.createProofSignature();
  }
}
