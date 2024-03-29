package uk.ac.ncl.cascade.zkpgs.keys;

import java.util.Map;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

/**
 * The interface organizes classes that offer access to vertex and edge bases.
 */
public interface IBaseProvider {
	
	/**
	 * Returns the vertex base according to the index parameter.
	 *
	 * @param index the index of the base
	 * @return the vertex base
	 */
	BaseRepresentation getVertexBase(int index);
	
	/**
	 * Returns the edge base according to the index parameter.
	 *
	 * @param index the index
	 * @return the edge base
	 */
	BaseRepresentation getEdgeBase(int index);
	
	/**
	 * Chooses uniformly at random a vertex base without replacement, that is, excluding ones stated as being excludedBases.
	 *
	 * @param excludedBaseMap Map of bases to exclude
	 * @return BaseRepresentation of a fresh vertex base.
	 */
	BaseRepresentation getRandomVertexBase(Map<URN, BaseRepresentation> excludedBaseMap);
	
	/**
	 * Chooses uniformly at random an edge base without replacement, that is, excluding ones stated as being excludedBases.
	 *
	 * @param excludedBaseMap Map of bases to exclude
	 * @return BaseRepresentation of a fresh edge base.
	 */
	BaseRepresentation getRandomEdgeBase(Map<URN, BaseRepresentation> excludedBaseMap);
	
	/**
	 * Chooses uniformly at random a vertex base with replacement.
	 *
	 * @return BaseRepresentation of a random vertex base.
	 */
	BaseRepresentation getRandomVertexBase();
	
	/**
	 * Chooses uniformly at random an edge base with replacement.
	 *
	 * @return BaseRepresentation of a random edge base.
	 */
	BaseRepresentation getRandomEdgeBase();
	
	/**
	 * Checks whether the mentioned base is a legal base under this base provider.
	 * 
	 * @param base BaseRepresentation to be checked.
	 * 
	 * @return <tt>true</tt> if and only if the base is recognized by the IBaseProvider (e.g., an ExtendedPublicKey).
	 */
	boolean isValidBase(BaseRepresentation base);
	
	/**
	 * Checks whether the mentioned base is a legal base under this base provider.
	 * 
	 * @param base BaseRepresentation to be checked.
	 * 
	 * @return <tt>true</tt> if and only if the base is recognized by the IBaseProvider (e.g., an ExtendedPublicKey).
	 */
	boolean isValidBase(GroupElement base);
}
