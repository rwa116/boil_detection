package boil_detection_project;

import java.util.ArrayList;

public class SourceHandler {
	
	protected SourceFinder sourceFinder;
	
	SourceHandler() {
		sourceFinder = new SourceFinder();
	}
	
	ArrayList<Source> GetSources(Sink sink) {
		ArrayList<Source> discoveredSources = new ArrayList<Source>();
		
		sourceFinder.FindSources(sink.refLocation, sink.arguments);
		// TODO: Implement stack behavior, calling FindSources(stack.top()) which
		// returns sources and a list of parameters that still need to be found
		
		return discoveredSources;
	}
}
