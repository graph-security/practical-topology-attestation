package uk.ac.ncl.cascade.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPrivateKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.orchestrator.RecipientOrchestrator;
import uk.ac.ncl.cascade.zkpgs.orchestrator.SignerOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.NumberConstants;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class SignerPrivateKeyTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private SignerKeyPair signerKeyPair;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private ProofSignature proofSignature;
  private SignerOrchestrator signerOrchestrator;
  private RecipientOrchestrator recipientOrchestrator;
  private GroupElement baseR0;
  private SignerPublicKey publicKey;
  private SignerPrivateKey privateKey;
  private QRGroupPQ group;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    privateKey = signerKeyPair.getPrivateKey();
    publicKey = signerKeyPair.getPublicKey();
    group = (QRGroupPQ) privateKey.getGroup();
  }

  @Test
  void getpPrime() {
    BigInteger pPrime = privateKey.getPPrime();
    assertNotNull(pPrime);
    assertEquals(keyGenParameters.getL_n() / 2, pPrime.bitLength() + 1);
    BigInteger p = group.getP();
    BigInteger pPrimeTest = p.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue());

    assertEquals(pPrimeTest, pPrime);
  }

  @Test
  void getqPrime() {
    BigInteger qPrime = privateKey.getQPrime();

    assertNotNull(qPrime);
    assertEquals(keyGenParameters.getL_n() / 2, qPrime.bitLength() + 1);

    BigInteger q = group.getQ();
    BigInteger qPrimeTest = q.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue());

    assertEquals(qPrimeTest, qPrime);
  }

  @Test
  void getX_r() {
    BigInteger x_r = privateKey.getX_r();
    assertNotNull(x_r);

  }

  @Test
  void getX_r0() {
    BigInteger x_r0 = privateKey.getX_r0();
    assertNotNull(x_r0);
  }

  @Test
  void getX_rZ() {
    BigInteger x_rZ = privateKey.getX_rZ();
    assertNotNull(x_rZ);
  }
}
