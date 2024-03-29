package boil_detection_project;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FunctionHandler {
	private HashSet<Function> functionSet = new HashSet<Function>();
	private static HashSet<String> knownSinks = new HashSet<String>();
	
	static { // All supported functions
//		knownSinks.add("strcpy");
//		knownSinks.add("strncpy");
//		knownSinks.add("strlcpy");
//		knownSinks.add("strcat");
//		knownSinks.add("strncat");
//		knownSinks.add("strlcat");
//		knownSinks.add("wcscpy");
//		knownSinks.add("wcsncpy");
//		knownSinks.add("wcscat");
//		knownSinks.add("wcsncat");
//		knownSinks.add("memcpy");
//		knownSinks.add("memmove");
//		knownSinks.add("gets");
//		knownSinks.add("fgets");
		knownSinks.add("__strcat_sse2");
	}
	
	public HashSet<Sink> findCalledFunctions() {
		HashSet<Sink> discoveredFunctions = new HashSet<Sink>();
		HashSet<String> duplicates = new HashSet<String>();
		FunctionIterator functions = Analyzer.Listing.getFunctions(true);
		int numFunctions = 0;
		
		while(functions.hasNext()) {
			Function function = functions.next();
//			Set<Function> calledFunctions = function.getCalledFunctions(Analyzer.tMonitor);
//			for(Function cFunc : calledFunctions)
//			if(knownSinks.contains(cFunc.getName()) && !duplicates.contains(cFunc.getName())) {
			if(!duplicates.contains(function.getName())) {
				duplicates.add(function.getName());
				
				discoveredFunctions.add(new Sink(function.getName(), function, function.getParameters()));
			}
			numFunctions++;
		}
		
		System.out.println("Number of functions: " + numFunctions);
		return discoveredFunctions;
	}
	
	public void FindOverflow(Sink sink) {
		// TODO: Takes in a Sink object and writes overflow details to a file
	}
	
}