package uk.ac.ncl.cascade.zkpgs.graph;

import uk.ac.ncl.cascade.zkpgs.encoding.IGraphEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.GSInternalError;
import uk.ac.ncl.cascade.zkpgs.util.Assert;

import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;
import org.jgrapht.io.GraphMLImporter;

/**
 * Encapsulates a graph of the graph signature scheme.
 *
 * <p>The method factory method createGraph(String filename) is used to instantiate such a graph
 * from a serialized graphml representation.
 *
 * @param <V> vertex type, required to be a subclass of GSVertex
 * @param <E> edge type, required to be a subclass of GSEdge
 */
public class GSGraph<
V extends GSVertex,
E extends GSEdge>
implements Serializable, Cloneable {

	/** */
	private static final long serialVersionUID = -3556647651640740630L;

	private DefaultUndirectedGraph<V, E> graph;
	
	private boolean isEncoded = false;

	/**
	 * Creates a new GSGraph with the corresponding vertices and edges after parsing a graphml file.
	 *
	 * @param graph the graph
	 */
	GSGraph(DefaultUndirectedGraph<V, E> graph) {
		super();
		this.graph = graph;
	}

	/**
	 * Factory method that creates a graph structure with a number of vertices and edges after
	 * importing the graphml file.
	 *
	 * @param graphFile the graph file
	 * @return GSGraph encapsulating a jgrapht graph
	 */
	public static GSGraph<GSVertex, GSEdge> createGraph(final String graphFile)
			throws ImportException {
		DefaultUndirectedGraph<GSVertex, GSEdge> graph = new DefaultUndirectedGraph<>(GSEdge.class);

		GraphMLImporter<GSVertex, GSEdge> importer = GraphMLProvider.createImporter();
        InputStream is = GraphMLProvider.getGraphMLStream(graphFile);
		importer.importGraph(graph, is);

		return new GSGraph<GSVertex, GSEdge>(graph);
	}

	/**
	 * Encodes a graph that has been constructed from an imported graphml file with a specified encoding. 
	 * Vertex and label representatives are obtained from an IGraphEncoding.
	 *
	 * @param encoding an IGraphEncoding which is meant to encode this graph.
	 * 
	 * @throws EncodingException if the encoding cannot encode a given vertex id or label String
	 * with a prime number. The encoding is usually on a finite set of distinct strings.
	 * Thereby, an EncodingException will occur if a vertex id or label is requested which is not
	 * in this finite set.
	 * 
	 * @post The GSGraph will be marked as having been successfully encoded if and only if
	 * the encodeGraph() method was completed without EncodingException.
	 */
	public void encodeGraph(IGraphEncoding encoding) throws EncodingException {
		Assert.notNull(encoding, "Method encodeGraph() called with a null encoding.");
		try {
		encodeVertices(encoding);
		encodeEdges(encoding);
		} catch (EncodingException e) {
			throw e;
		}
		this.isEncoded = true;
	}

	private void encodeVertices(IGraphEncoding encoding) throws EncodingException {
		Set<V> vertexSet = this.graph.vertexSet();
		for (V vertex : vertexSet) {
			encodeVertex(vertex, encoding);
		}
	}

	/**
	 * Encodes a single vertex with a given encoding.
	 * 
	 * @param vertex to be encoded
	 * @param encoding IGraphEncoding to be used
	 * 
	 * @throws EncodingException if this particular vertex cannot be encoded, either
	 * because the vertex id or a label string is not found represented in the encoding.
	 */
	private void encodeVertex(V vertex, IGraphEncoding encoding) throws EncodingException {
		// Set Vertex Representative
		vertex.setVertexRepresentative(encoding.getVertexRepresentative(vertex.getId()));

		// List of Vertex Label Representatives
		ArrayList<BigInteger> vertexLabelRepresentatives = new ArrayList<>();
		if ((vertex.getLabels() != null) && (!vertex.getLabels().isEmpty())) {
			for (String label : vertex.getLabels()) {
				BigInteger labelRepresentative = encoding.getVertexLabelRepresentative(label);
				Assert.notNull(
						labelRepresentative, "The encoding returned null as a vertex label.");
				vertexLabelRepresentatives.add(labelRepresentative);
			}
		}
		vertex.setLabelRepresentatives(vertexLabelRepresentatives);
	}

	private void encodeEdges(IGraphEncoding encoding) throws EncodingException {
		Set<E> edgeSet = this.graph.edgeSet();
		for (E edge : edgeSet) {
			encodeEdge(edge, encoding);
		}
	}

	/**
	 * Encodes a single edge with a given encoding.
	 * 
	 * @param edge to be encoded
	 * @param encoding IGraphEncoding to be used
	 * 
	 * @throws EncodingException if this particular edge cannot be encoded, because
	 * a label string is not found represented in the encoding.
	 */
	private void encodeEdge(E edge, IGraphEncoding encoding) throws EncodingException {
		// Vertex representatives already encoded by the GSVertex instances referenced by the edge 

		// List of Edge Label Representatives
		ArrayList<BigInteger> edgeLabelRepresentatives = new ArrayList<>();
		if ((edge.getLabels() != null) && (!edge.getLabels().isEmpty())) {
			for (String label : edge.getLabels()) {
				BigInteger labelRepresentative = encoding.getEdgeLabelRepresentative(label);
				Assert.notNull(
						labelRepresentative, "The encoding returned null as an edge label.");
				edgeLabelRepresentatives.add(labelRepresentative);
			}
		}
		edge.setLabelRepresentatives(edgeLabelRepresentatives);
	}

	/**
	 * Returns the encapsulated Graph instance.
	 *
	 * @return the graph
	 */
	public Graph<V, E> getGraph() {
		return graph;
	}
	
	/**
	 * Checks whether IGraphEncoding on this GSGraph has already been completed
	 * successfully.
	 * 
	 * @return <tt>true</tt> if encodeGraph() was called with a non-null IGraphEncoding
	 * and completed without an EncodingException being thrown.
	 */
	public boolean isEncoded() {
		return isEncoded;
	}

	@SuppressWarnings("unchecked")
	@Override
	public GSGraph<V, E> clone() {
		GSGraph<V, E> theClone = null;

		try {
			theClone = (GSGraph<V, E>) super.clone();
		} catch (CloneNotSupportedException e) {
			// Should never happen
			throw new GSInternalError(e);
		}

		// Cloning mutable members
		theClone.graph = (DefaultUndirectedGraph<V, E>) graph.clone();
		return theClone;
	}
	

	/**
	 * Returns a vertex based on the vertex id, that is, the String identifier of V (usually a GSVertex).
	 * 
	 * @param vertexId The id of the vertex in question.
	 * @return A clone of V (the GSVertex) if one is found, null otherwise.
	 */
	public V getVertexById(String vertexId) {
		V vertexFound = null;
		
		Iterator<V> vertexIterator = graph.vertexSet().iterator();
		while (vertexIterator.hasNext()) {
			V v = (V) vertexIterator.next();
			if (v.getId().equals(vertexId)) {
				try {
				vertexFound = (V) v.clone();
				} catch (ClassCastException e) {
					throw new GSInternalError("The vertex found could not be class-cast to the GSVertex class specified.");
				}
			}
		}
		
		return vertexFound;
	}
}
