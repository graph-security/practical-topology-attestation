package uk.ac.ncl.cascade.zkpgs.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRElementN;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroup;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroupN;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** */
class ProofStoreTest {
  ProofStore<Object> proofStore;
  QRGroup testGroup;
  GroupElement testS;
  GroupElement testR;

  @BeforeEach
  void setUp() {
    proofStore = new ProofStore<Object>(10);
    testGroup = new QRGroupN(BigInteger.valueOf(77));
    testS = new QRElementN(testGroup, BigInteger.valueOf(60));
    testR = new QRElementN(testGroup, BigInteger.valueOf(58));
  }

  @Test
  @DisplayName("Test add a new object in the proof store")
  void put() throws Exception {

    proofStore.storeUnsafe("biginteger.2", BigInteger.valueOf(1));
    BigInteger testM = CryptoUtilsFacade.computeRandomNumber(1024);
    proofStore.storeUnsafe("test.M", testM);
    assertEquals(2, proofStore.size());
  }

  @Test
  @DisplayName("Test throwing an exception when adding the same object in the proof store")
  void storeSameElement() throws Exception {

    proofStore.storeUnsafe("biginteger.2", BigInteger.valueOf(1));
    GSCommitment gsCommitment =
        GSCommitment.createCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.storeUnsafe("commitments.ci", gsCommitment);

    Throwable exception =
        assertThrows(
            Exception.class,
            () -> {
              proofStore.storeUnsafe("biginteger.2", BigInteger.valueOf(2));
            });

    String exceptionMessage = exception.getMessage();
    Boolean containsString = exceptionMessage.contains("with type URN was already added");
    assertTrue(containsString);

    assertEquals(2, proofStore.size());
  }

  @Test
  @DisplayName("Test retrieve an object from the store")
  void retrieve() throws Exception {

    proofStore.storeUnsafe("biginteger.2", BigInteger.valueOf(1));

    GSCommitment gsCommitment = GSCommitment.createCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.storeUnsafe("commitments.ci", gsCommitment);

    BigInteger el = (BigInteger) proofStore.retrieveUnsafe("biginteger.2");
    assertNotNull(el);
  }

  @Test
  @DisplayName("Test proof store for adding objects")
  void add() throws ProofStoreException {

    proofStore.add(URN.createUnsafeZkpgsURN("biginteger.2"), BigInteger.valueOf(1));

    GSCommitment gsCommitment = GSCommitment.createCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.storeUnsafe("commitments.ci", gsCommitment);

    BigInteger el = (BigInteger) proofStore.retrieveUnsafe("biginteger.2");
    assertNotNull(el);
    assertEquals(2, proofStore.size());
  }

  @Test
  @DisplayName("Test proof store for removing objects")
  void remove() throws ProofStoreException {
    proofStore.add(URN.createUnsafeZkpgsURN("biginteger.2"), BigInteger.valueOf(1));

    GSCommitment gsCommitment =
        GSCommitment.createCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.storeUnsafe("commitments.ci", gsCommitment);

    proofStore.remove(URN.createUnsafeZkpgsURN("biginteger.2"));

    assertEquals(1, proofStore.size());
  }

  @Test
  @DisplayName("Test proof store for outputting that the it is empty")
  void isEmpty() throws ProofStoreException {
    proofStore.add(URN.createUnsafeZkpgsURN("biginteger.2"), BigInteger.valueOf(1));

    assertEquals(1, proofStore.size());

    proofStore.remove(URN.createUnsafeZkpgsURN("biginteger.2"));

    assertTrue(proofStore.isEmpty());
  }

  @Test
  @DisplayName("Test proof store getElement for correct collection size")
  void getElements() throws ProofStoreException {
    proofStore.add(URN.createUnsafeZkpgsURN("biginteger.2"), BigInteger.valueOf(1));

    GSCommitment gsCommitment =
        GSCommitment.createCommitment(testR, BigInteger.ONE, BigInteger.TEN, testS, testGroup.getModulus());
    proofStore.storeUnsafe("commitments.ci", gsCommitment);

    assertNotNull(proofStore.getElements());
    assertEquals(2, proofStore.getElements().size());
  }
}
