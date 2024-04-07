package boil_detection_project;

import java.util.HashSet;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;

public class FunctionHandler {
	private Listing listing;
	
	public FunctionHandler(Listing listing) {
		this.listing = listing;
	}
	
	public HashSet<Function> findCalledFunctions() {
		HashSet<Function> discoveredFunctions = new HashSet<Function>();
		HashSet<String> duplicates = new HashSet<String>();
		FunctionIterator functions = listing.getFunctions(true);
		int numFunctions = 0;
		
		while(functions.hasNext()) {
			Function function = functions.next();
			if(function.isExternal()) {
				continue;
			}
			if(!duplicates.contains(function.getName())) {
				duplicates.add(function.getName());
				
				discoveredFunctions.add(function);
			}
			numFunctions++;
		}
		
		System.out.println("Number of functions: " + numFunctions);
		return discoveredFunctions;
	}
	
}