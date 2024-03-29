package uk.ac.ncl.cascade.zkpgs.graph;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.math.BigInteger;
import java.util.ArrayList;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.ac.ncl.cascade.zkpgs.graph.GSEdge;
import uk.ac.ncl.cascade.zkpgs.graph.GSVertex;

class GSEdgeTest {

  private GSVertex e_i;
  private GSVertex e_j;
  private GSEdge gsEdge;

  @BeforeEach
  void setUp() {
    e_i = new GSVertex("1", new ArrayList<>());
    e_i.setVertexRepresentative(BigInteger.valueOf(6701));
    e_j = new GSVertex("2", new ArrayList<>());
    e_j.setVertexRepresentative(BigInteger.valueOf(7703));
  }

  @Test
  void getE_i() {
    gsEdge = new GSEdge(e_i, e_j);
    assertNotNull(gsEdge.getV_i());
    assertEquals(BigInteger.valueOf(6701), gsEdge.getV_i().getVertexRepresentative());
  }

  @Test
  void getE_j() {
    gsEdge = new GSEdge(e_i, e_j);
    assertNotNull(gsEdge.getV_j());
    assertEquals(BigInteger.valueOf(7703), gsEdge.getV_j().getVertexRepresentative());
  }

  @Test
  void getLabelRepresentatives() {
    gsEdge = new GSEdge(e_i, e_j);
    ArrayList<BigInteger> labelRepresentatives = new ArrayList<>();
    labelRepresentatives.add(BigInteger.valueOf(6113));
    gsEdge.setLabelRepresentatives(labelRepresentatives);
    assertNotNull(gsEdge.getLabelRepresentatives());
    assertEquals(BigInteger.valueOf(6113), gsEdge.getLabelRepresentatives().get(0));
  }

  @Test
  void setLabelRepresentatives() {
    gsEdge = new GSEdge(e_i, e_j);
    ArrayList<BigInteger> labelRepresentatives = new ArrayList<>();
    labelRepresentatives.add(BigInteger.valueOf(7243));
    gsEdge.setLabelRepresentatives(labelRepresentatives);
    assertNotNull(gsEdge.getLabelRepresentatives());
    assertEquals(BigInteger.valueOf(7243), gsEdge.getLabelRepresentatives().get(0));
  }

  @Test
  void getLabels() {
    gsEdge = new GSEdge(e_i, e_j);
    ArrayList<String> labels = new ArrayList<>();
    labels.add("UK");
    gsEdge.setLabels(labels);
    assertNotNull(gsEdge.getLabels());
    assertEquals("UK", gsEdge.getLabels().get(0));
  }
}
