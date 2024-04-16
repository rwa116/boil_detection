package boil_detection_project;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;

public class Analyzer extends GhidraScript{
	private DecompInterface decomp;
	
	private static Listing listing;
	private static TaskMonitor taskMonitor;
	
	private static final boolean VERBOSE_PRINT = false;
	
	private void decompilerSetup() {
		decomp = new DecompInterface();
		
		DecompileOptions options;
		options = new DecompileOptions();
		
		decomp.setOptions(options);
		decomp.toggleCCode(false);
		decomp.toggleSyntaxTree(true);
		decomp.setSimplificationStyle("decompile");
		decomp.openProgram(currentProgram);
	}
	
	private void globalSetup() {
		listing = currentProgram.getListing();
		taskMonitor = monitor;
	}

	@Override
	protected void run() throws Exception {
		long startTime = System.currentTimeMillis();
		decompilerSetup();
		globalSetup();
		HashSet<Function> discoveredFunctions;
		
		FunctionHandler sinkHandler = new FunctionHandler(listing);
		LoopHandler loopHandler = new LoopHandler(taskMonitor, VERBOSE_PRINT);
		BoilDetector boilDetector = new BoilDetector(VERBOSE_PRINT);
		
		discoveredFunctions = sinkHandler.findCalledFunctions();
		
				
		int numBoils = 0;
		int numLoops = 0;
		Set<Function> bops = new HashSet<Function>();
		
		for(Function func : discoveredFunctions) {
			if(VERBOSE_PRINT) {
				System.out.println("Discovered function: " + func.getName());
			}
			
			Function currentFunction = func;
			HighFunction highFunction = decomp.decompileFunction(currentFunction, 300, monitor).getHighFunction();
			if (VERBOSE_PRINT) {
				Iterator<PcodeOpAST> pcodes = highFunction.getPcodeOps();
				while(pcodes.hasNext()) {
					System.out.println(pcodes.next());
				}
			}
			
			
			GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> CFG = loopHandler.generateCFG(highFunction);
			GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> domTree = loopHandler.generateDominatorTree(CFG);
			List<GEdge<PcodeBlockBasic>> backEdges = loopHandler.identifyBackEdges(CFG, domTree);
			
			List<GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>>> loopBodyCFGs = loopHandler.findLoopBodyCFGs(CFG, domTree, backEdges);
			numLoops += loopBodyCFGs.size();
			
			if(VERBOSE_PRINT) {
				System.out.println("Loop body CFGs:");
				for (GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> loopBodyCFG : loopBodyCFGs) {
					System.out.println(" ");
					System.out.println("Loop body CFG:");
					PcodeBlockBasic entry = loopBodyCFG.getVertices().iterator().next();
					while (loopBodyCFG.getInEdges(entry).size() != 0) {
						entry = loopBodyCFG.getPredecessors(entry).iterator().next();
					}
					while(loopBodyCFG.getOutEdges(entry).size() > 0){
						System.out.println("Block: " + entry);
						Iterator<PcodeOp> it = entry.getIterator();
						while (it.hasNext()) {
							System.out.println(it.next());
						}
						entry = loopBodyCFG.getSuccessors(entry).iterator().next();
					}
					System.out.println("Block: " + entry);
					Iterator<PcodeOp> it = entry.getIterator();
					while (it.hasNext()) {
						System.out.println(it.next());
					}
				}
			}
			
			// Find all loop body CFGs that contain a store
			List<GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>>> potentialBoilCFGs = new ArrayList<>();
			for (GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> loopBodyCFG : loopBodyCFGs) {
				if (boilDetector.hasStore(loopBodyCFG)) {
					potentialBoilCFGs.add(loopBodyCFG);
				}
			}
			
			// Check if each loop body CFG that contains a store is a BOIL
			for (GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> potentialBoilCFG : potentialBoilCFGs) {
				if (boilDetector.isBoil(potentialBoilCFG)) {
					System.out.println("Boil detected in " + currentFunction.getName());
					numBoils++;
					bops.add(currentFunction);
				}
			}
		}
		long endTime = System.currentTimeMillis();
		long elapsedTime = endTime - startTime;
		
		 // Print out important statistics
		System.out.println("Total LOOPs detected: " + numLoops);
		System.out.println("Total BOILs detected: " + numBoils);
		System.out.println("Percent of Loops that are BOILs: " + ((double)numBoils / numLoops) * 100 + "%");
		System.out.println("Total Functions detected: " + discoveredFunctions.size());
		System.out.println("Total BOP Functions detected: " + bops.size());
		System.out.println("Percent of Functions that are BOPs: " + ((double)bops.size() / discoveredFunctions.size()) * 100 + "%");
		for (Function f : bops) {
			System.out.println("BOP function detected: " + f.getName());
		}
		System.out.println("Total time: " + elapsedTime + " ms");
		
	}

}
