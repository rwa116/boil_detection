package boil_detection_project;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;

public class Sink {
	public String name;
	public Function functionRef;
	public List<Parameter> arguments;
	
	public Sink(String name, Function function, Parameter[] arguments) {
		this.name = name;
		this.functionRef = function;
		this.arguments = Arrays.asList(arguments);
	}
	
	public void CalculateOverflow() {
		// TODO: write to file about possible overflows
		if(arguments.size() == 2) { // 2 argument sink, has only dest and src char*
			Parameter first = arguments.get(0);
		}
	}
}
