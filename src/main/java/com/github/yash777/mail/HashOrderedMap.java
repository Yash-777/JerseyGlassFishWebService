package com.github.yash777.mail;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * OrderedMap using a HashMap for its implementation.
 */
public class HashOrderedMap<K, V> implements OrderedMap<K, V> {
	private Map<K, V> map;

	private ArrayListOrderedSet orderSet;

	public HashOrderedMap() {
		super();

		map = new HashMap<K, V>();
		orderSet = new ArrayListOrderedSet();
	}

	public void clear() {
		map.clear();
		orderSet.clear();
	}

	public boolean containsKey(Object key) {
		return map.containsKey(key);
	}

	public boolean containsValue(Object value) {
		return map.containsValue(value);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public Set entrySet() {
		return map.entrySet();
	}

	public boolean equals(Object o) {
		return map.equals(o);
	}

	public V get(Object key) {
		return map.get(key);
	}

	public int hashCode() {
		return map.hashCode();
	}

	public boolean isEmpty() {
		return map.isEmpty();
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public Set keySet() {
		return orderSet;
	}

	public V put(K key, V value) {
		V oldValue = map.get(key);
		add(key, value);

		return oldValue;
	}

	public boolean add(K key, V value) {
		if (!orderSet.add(key))
			return false;

		map.put(key, value);
		return true;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void putAll(Map<? extends K, ? extends V> t) {
		for (Iterator i = t.keySet().iterator(); i.hasNext();) {
			K key = (K) i.next();
			add(key, t.get(key));
		}
	}

	public V remove(Object key) {
		orderSet.remove(key);
		return map.remove(key);
	}

	public int size() {
		return map.size();
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public Collection values() {
		return map.values();
	}

}