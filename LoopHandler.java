package boil_detection_project;

import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphFactory;
import ghidra.graph.GraphAlgorithms;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LoopHandler {
	private TaskMonitor taskMonitor;
	private boolean VERBOSE_PRINT = false;
	
	public LoopHandler(TaskMonitor taskMonitor, boolean verbose) {
		this.taskMonitor = taskMonitor;
		this.VERBOSE_PRINT = verbose;
	}
	
	public GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> generateDominatorTree(GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> flowGraph) {
		
		GDirectedGraph<PcodeBlockBasic, GEdge<PcodeBlockBasic>> domTree;
		try {
			domTree = GraphAlgorithms.findDominanceTree(flowGraph, taskMonitor);
		} catch (Exception e) {
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
				if (block.getOutSize() == 1 && block.equals(block.getOut(i))) { // Ignore infinite loops, this causes issues with dominance trees
					continue;
				}
				flowGraph.addEdge(new DefaultGEdge<PcodeBlockBasic>(block, (PcodeBlockBasic) block.getOut(i)));
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
					if(GraphAlgorithms.findDominance(domTree, child, taskMonitor).contains(vertex)) {
						// Child is also a dominator; loop detected
						if (CFG.findEdge(vertex, child) != null) {
							if(VERBOSE_PRINT) {
								System.out.println("Found back edge: " + vertex + " -> " + child);
							}
							backEdges.add(CFG.findEdge(vertex, child));
						}
					}
				} catch (CancelledException e) {
					e.printStackTrace();
					throw new Error("Could not find dominators of vertex: " + vertex);
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
			PcodeBlockBasic source = backEdge.getEnd();
			
			traversalStack.push(header);
			
			while(!traversalStack.empty()) {
				PcodeBlockBasic currentNode = traversalStack.pop();
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
			if(VERBOSE_PRINT) {
			    System.out.println("Loop body CFG:");
			}
			while(!loopBody.isEmpty()) {
				PcodeBlockBasic vertex = loopBody.pop();
				if(VERBOSE_PRINT) {
					System.out.println(vertex);
				}
				loopBodyCFG.addVertex(vertex);
				if (!loopBody.isEmpty()) {
					loopBodyCFG.addEdge(new DefaultGEdge<PcodeBlockBasic>(vertex, loopBody.peek()));
				}
			}
			
			loopBodyCFGs.add(loopBodyCFG);
		}
		
		return loopBodyCFGs;
	}

}
