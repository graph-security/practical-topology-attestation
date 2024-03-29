package uk.ac.ncl.cascade.orchestrator;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.orchestrator.GroupSetupProverOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.GroupSetupProver;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class GroupSetupProverOrchestratorTest {
  private SignerKeyPair gsk;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private GroupSetupProverOrchestrator gsProverOrchestrator;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException, EncodingException {
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
  }

  @BeforeEach
  void setup() {
    proofStore = new ProofStore<Object>();
    gsProverOrchestrator = new GroupSetupProverOrchestrator(extendedKeyPair, proofStore);
  }

  @Test
  @DisplayName("Test preChallengePhase for the GroupSetupProverOrchestrator")
  void executePreChallengePhase() {
    gsProverOrchestrator.executePreChallengePhase();
    String tilderURN = URNType.buildURNComponent(URNType.TILDER, GroupSetupProver.class);
    BigInteger tilder = (BigInteger) proofStore.retrieve(tilderURN);
    assertNotNull(tilder);

    String tilder_0URN = URNType.buildURNComponent(URNType.TILDER0, GroupSetupProver.class);
    BigInteger tilder_0 = (BigInteger) proofStore.retrieve(tilder_0URN);
    assertNotNull(tilder_0);

    String tilder_ZURN = URNType.buildURNComponent(URNType.TILDERZ, GroupSetupProver.class);
    BigInteger tilder_Z = (BigInteger) proofStore.retrieve(tilder_ZURN);
    assertNotNull(tilder_Z);
  }

  @Test
  @DisplayName("Test compute challenge")
  void computeChallenge() {
    gsProverOrchestrator.executePreChallengePhase();
    BigInteger cChallenge = gsProverOrchestrator.computeChallenge();
    assertNotNull(cChallenge);
  }

  @Test
  @DisplayName("Test postChallengePhase for the GroupSetupOrchestrator")
  void executePostChallengePhase() {
    gsProverOrchestrator.executePreChallengePhase();
    BigInteger cChallenge = gsProverOrchestrator.computeChallenge();
    assertNotNull(cChallenge);
    gsProverOrchestrator.executePostChallengePhase(cChallenge);
  }

  @Test
  @DisplayName("Test create proof signature")
  void createProofSignature() {
    gsProverOrchestrator.executePreChallengePhase();
    BigInteger cChallenge = gsProverOrchestrator.computeChallenge();
    gsProverOrchestrator.executePostChallengePhase(cChallenge);
    ProofSignature proofSignature = gsProverOrchestrator.createProofSignature();
    assertNotNull(proofSignature);
    Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();

    assertNotNull(proofElements);
    assertTrue(proofElements.size() > 0);
  }
}
