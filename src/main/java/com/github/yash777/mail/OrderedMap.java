package com.github.yash777.mail;

import java.util.Map;

/**
 * Map that maintains an order for its keys.
 * 
 */
public interface OrderedMap<K, V> extends Map<K, V> {
	/**
	 * Adds a key-value pair to the OrderedMap.
	 * 
	 * @param key
	 *            the key for the entry.
	 * @param value
	 *            the value for the entry.
	 * @return true, if the key wasn't in the Map until now, false otherwise
	 */
	public boolean add(K key, V value);
}

