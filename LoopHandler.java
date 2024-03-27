package boil_detection_project;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphFactory;
import ghidra.graph.GraphAlgorithms;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;

public class LoopHandler {
	
	public GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> generateDominatorTree(GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> flowGraph) {
		
		GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> domTree;
		try {
			domTree = GraphAlgorithms.findDominanceTree(flowGraph, Analyzer.tMonitor);
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new Error("Could not construct dominance tree");
		}
		
		return domTree;
	}
	
	public GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> generateCFG(HighFunction highFunc) {
		List<PcodeBlockBasic> basicBlocks = highFunc.getBasicBlocks();
		GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> flowGraph = GraphFactory.createDirectedGraph();
		for(PcodeBlockBasic block : basicBlocks) {
			flowGraph.addVertex(block);
			for(int i = 0; i < block.getOutSize(); i++) {
				flowGraph.addEdge(new DefaultGEdge(block, block.getOut(i)));
			}
		}
		
		return flowGraph;
	}
	
	public List<GEdge<PcodeBlockBasic>> identifyBackEdges(GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> CFG,
			GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> domTree) {
		List<GEdge<PcodeBlockBasic>> backEdges = new ArrayList<>();
		for(PcodeBlockBasic vertex : CFG.getVertices()) {
			for(PcodeBlockBasic child : CFG.getSuccessors(vertex)) {
				try {
					
//					System.out.println("Finding dominators of child " + child);
//					System.out.println("Goal vertex: " + vertex);
//					for (PcodeBlockBasic dom : GraphAlgorithms.findDominance(domTree, child, Analyzer.tMonitor)) {
//						System.out.println("Dominator: " + dom);
//					}
					
					if(GraphAlgorithms.findDominance(domTree, child, Analyzer.tMonitor).contains(vertex)) {
						System.out.println("Found back edge: " + vertex + " -> " + child);
						// Child is also a dominator; loop detected
						if (CFG.findEdge(vertex, child) != null) {
							System.out.println("CONFIRMED back edge: " + vertex + " -> " + child);
							backEdges.add(CFG.findEdge(vertex, child));
						}
					}
				} catch (CancelledException e) {
					e.printStackTrace();
					throw new Error("Could not find dominators of vertex " + vertex);
				}
			}
		}
		return backEdges;
	}
	
	public List<GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>>> findLoopBodyCFGs(
			GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> CFG,
			GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> domTree,
			List<GEdge<PcodeBlockBasic>> backEdges) {
		
		List<GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>>> loopBodyCFGs = new ArrayList<>();
		
		for(GEdge<PcodeBlockBasic> backEdge : backEdges) {
			Stack<PcodeBlockBasic> loopBody = new Stack<>();
			List<PcodeBlockBasic> visited = new ArrayList<>();
			Stack<PcodeBlockBasic> traversalStack = new Stack<>();
			PcodeBlockBasic header = backEdge.getStart();
			PcodeBlockBasic source = backEdge.getEnd(); // loop header
			
			traversalStack.push(header);
			
			while(!traversalStack.empty()) {
				PcodeBlockBasic currentNode = traversalStack.pop();
				//System.out.println("Current node: " + currentNode);
				if(visited.contains(currentNode)) {
                    continue;
                }
				
				visited.add(currentNode);
				loopBody.push(currentNode);
				
				for (PcodeBlockBasic pred : domTree.getPredecessors(currentNode)) {
					if (!visited.contains(pred) && currentNode != source) {
						traversalStack.push(pred);
					}
				}
			}
			
			
			// Construct CFG of loop body
			GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> loopBodyCFG = GraphFactory.createDirectedGraph();
			System.out.println("Loop body:");
			while(!loopBody.isEmpty()) {
				PcodeBlockBasic vertex = loopBody.pop();
				System.out.println(vertex);
				loopBodyCFG.addVertex(vertex);
				if (!loopBody.isEmpty()) {
					loopBodyCFG.addEdge(new DefaultGEdge(vertex, loopBody.peek()));
				}
			}
			
			loopBodyCFGs.add(loopBodyCFG);
		}
		
		return loopBodyCFGs;
	}

}
