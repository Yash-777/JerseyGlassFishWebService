package com.github.yash777.mail;

import java.util.HashSet;
import java.util.Set;

public class SetInterFaceInternals {
	public static void main(String[] args) {
		String str = "Hai";
		System.out.println("Str:"+ str.length());
		
		Set<Integer> setA = new HashSet<Integer>();
		setA.add(1);
		System.out.println("setA:"+setA.size());
		
		int arr[] = {1,2,3,4};
		System.out.println("Arr:"+arr.length);
	}
}
