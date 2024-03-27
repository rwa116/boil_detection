package boil_detection_project;

import java.util.ArrayList;

/*
 * ./analyzeHeadless /home/ryan/code/cmpt_479/ ghidra_prac -process CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.out -postscript static_overflow_project.Analyzer
 */

// ./analyzeHeadless /home/ryan/code/cmpt_479/ ghidra_prac -process strings -postscript overflow_package.Analyzer
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;

public class Analyzer extends GhidraScript{
	public DecompInterface decomp;
	
	public static HashSet<Function> FunctionsUsed;
	public static Boolean SecondPass = false;
	public static Boolean OutputFile = false;
	public static Integer FindSourceLimit = 5;
	public static Listing Listing;
	public static AddressFactory AddressFactory;
	public static ReferenceManager ReferenceManager;
	public static String ProgramName;
	public static FlatProgramAPI FlatApi;
	public static TaskMonitor tMonitor;
	
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
		Listing = currentProgram.getListing();
		AddressFactory = currentProgram.getAddressFactory();
		ReferenceManager = currentProgram.getReferenceManager();
		ProgramName = currentProgram.getName();
		FlatApi = new FlatProgramAPI(currentProgram);
		tMonitor = monitor;
	}

	@Override
	protected void run() throws Exception {
		decompilerSetup();
		globalSetup();
		HashSet<Sink> discoveredSinks;
		
		FunctionHandler sinkHandler = new FunctionHandler();
		LoopHandler loopHandler = new LoopHandler();
		BoilDetector boilDetector = new BoilDetector();
		
		discoveredSinks = sinkHandler.findCalledFunctions();
		
		
		System.out.println("Hello!");
		
		for(Sink dis : discoveredSinks) {
			System.out.println("Discovered sink: " + dis.name);
			
			Function currentFunction = dis.functionRef;
			HighFunction highFunction = decomp.decompileFunction(currentFunction, 300, monitor).getHighFunction();
			Iterator<PcodeOpAST> pcodes = highFunction.getPcodeOps();
			while(pcodes.hasNext()) {
				System.out.println(pcodes.next());
			}
			
			GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> CFG = loopHandler.generateCFG(highFunction);
			GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> domTree = loopHandler.generateDominatorTree(CFG);
			List<GEdge<PcodeBlockBasic>> backEdges = loopHandler.identifyBackEdges(CFG, domTree);
			
			List<GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>>> loopBodyCFGs = loopHandler.findLoopBodyCFGs(CFG, domTree, backEdges);
			
//			for (GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> loopBodyCFG : loopBodyCFGs) {
//				for (PcodeBlockBasic v : loopBodyCFG.getVertices()) {
//					System.out.println(" ");
//					System.out.println(v);
//					Iterator<PcodeOp> it = v.getIterator();
//					while (it.hasNext()) {
//						System.out.println(it.next());
//					}
//					System.out.println(" ");
//				}
//			}
			
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
			
			List<GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>>> potentialBoilCFGs = new ArrayList<>();
			for (GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> loopBodyCFG : loopBodyCFGs) {
				if (boilDetector.hasStore(loopBodyCFG)) {
					System.out.println("Store detected in loop body");
					potentialBoilCFGs.add(loopBodyCFG);
				}
			}
			
			for (GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> potentialBoilCFG : potentialBoilCFGs) {
				if (boilDetector.isBoil(potentialBoilCFG)) {
					System.out.println("Boil detected");
				}
			}
			
//			
//			System.out.println("Dominance tree:");
//			for(PcodeBlockBasic v : domTree.getVertices()) {
//				System.out.println(" ");
//				System.out.println(v);
//				Iterator<PcodeOp> it = v.getIterator();
//				while(it.hasNext()) {
//					System.out.println(it.next());
//				}
//				System.out.println(" ");
//			}
//			
//			System.out.println("CFG:");
//			for (PcodeBlockBasic v : CFG.getVertices()) {
//				System.out.println(" ");
//				System.out.println(v);
//				Iterator<PcodeOp> it = v.getIterator();
//				while (it.hasNext()) {
//					System.out.println(it.next());
//				}
//				System.out.println(" ");
//			}
//			
//			if (backEdges.isEmpty()) {
//				System.out.println("No back edges detected");
//			}
//			for (GEdge<PcodeBlockBasic> backEdge : backEdges) {
//				System.out.println("Backedge detected: " + backEdge);
//			}
//			
//			for (GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> loopBodyCFG : loopBodyCFGs) {
//				System.out.println(" ");
//				for (PcodeBlockBasic v : loopBodyCFG.getVertices()) {
//					System.out.println(" ");
//					System.out.println(v);println
//					Iterator<PcodeOp> it = v.getIterator();
//					while (it.hasNext()) {
//						System.out.println(it.next());
//					}
//					System.out.println(" ");
//				}
//				System.out.println(" ");
//			}
//			break;
		}
		
	}


}
