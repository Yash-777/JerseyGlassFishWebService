package com.github.yash777.mail;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class ArrayListOrderedSet implements OrderedSet {
	private List<Object> entries;

	/**
	 * Simple constructor using an array list for its entries.
	 */
	public ArrayListOrderedSet() {
		super();
		entries = new ArrayList<Object>();
	}

	public int size() {
		return entries.size();
	}

	public void clear() {
		entries.clear();
	}

	public boolean isEmpty() {
		return entries.isEmpty();
	}

	public Object[] toArray() {
		return entries.toArray();
	}

	public boolean add(Object o) {
		// ignore existing entries to ensure Set interface contract
		if (entries.contains(o))
			return false;

		return entries.add(o);
	}

	public boolean contains(Object o) {
		return entries.contains(o);
	}

	public boolean remove(Object o) {
		return entries.remove(o);
	}

	@SuppressWarnings("unchecked")
	public boolean addAll(@SuppressWarnings("rawtypes") Collection c) {
		// Now what? suddenly the set interface contract is broken...
		return entries.addAll(c);
	}

	public boolean containsAll(@SuppressWarnings("rawtypes") Collection c) {
		return entries.containsAll(c);
	}

	public boolean removeAll(@SuppressWarnings("rawtypes") Collection c) {
		return entries.removeAll(c);
	}

	public boolean retainAll(@SuppressWarnings("rawtypes") Collection c) {
		return entries.retainAll(c);
	}

	public Iterator<Object> iterator() {
		return entries.iterator();
	}

	public Object[] toArray(Object[] a) {
		return entries.toArray(a);
	}

}