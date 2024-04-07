package boil_detection_project;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class BoilDetector {
	private boolean VERBOSE_PRINT;
	
	public BoilDetector(boolean verbose) {
		this.VERBOSE_PRINT = verbose;
	}
	
	public Boolean hasStore(GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> loopBodyCFG) {
		for (PcodeBlockBasic block : loopBodyCFG.getVertices()) {
			Iterator<PcodeOp> opIt = block.getIterator();
			while(opIt.hasNext()) {
				if (opIt.next().getOpcode() == PcodeOp.STORE) {
					return true;
				}
			}
		}
		return false;
	}
	
	public Boolean isBoil(GDirectedGraph<PcodeBlockBasic, DefaultGEdge<PcodeBlockBasic>> loopBodyCFG) {
		List<PcodeOp> instList = new ArrayList<PcodeOp>();
		Stack<PcodeOp> stores = new Stack<PcodeOp>();
		int storeCount = 0;
		
		// Add all instructions in the loop body to a list
		PcodeBlockBasic entry = loopBodyCFG.getVertices().iterator().next();
		while (loopBodyCFG.getInEdges(entry).size() != 0) {
			entry = loopBodyCFG.getPredecessors(entry).iterator().next();
		}
		while(loopBodyCFG.getOutEdges(entry).size() > 0){
			Iterator<PcodeOp> it = entry.getIterator();
			while (it.hasNext()) {
				PcodeOp op = it.next();
				if (op.getOpcode() == PcodeOp.STORE) {
					stores.push(op);
					storeCount++;
				}
				instList.add(op);
			}
			entry = loopBodyCFG.getSuccessors(entry).iterator().next();
		}
		Iterator<PcodeOp> it = entry.getIterator();
		while (it.hasNext()) {
			PcodeOp op = it.next();
			if (op.getOpcode() == PcodeOp.STORE) {
				stores.push(op);
				storeCount++;
			}
			instList.add(op);
		}
		
		CircularList<PcodeOp> instructions = new CircularList<PcodeOp>(instList);
		
		if(VERBOSE_PRINT) {
			System.out.println("Store count: " + storeCount);
		}
		while (!stores.isEmpty()) {
			List<Varnode> depChain = new ArrayList<Varnode>();
			List<PcodeOp> pChain = new ArrayList<PcodeOp>();
			PcodeOp store = stores.pop();
			if(VERBOSE_PRINT) {
				System.out.println("Store: " + store + " memory offset: " + store.getInput(1));
			}
			if (isSelfDependent(store, depChain, pChain, instructions)) {
				if (VERBOSE_PRINT) {
					System.out.println("Dependency chain: " + depChain);
				}
				System.out.println("Dependency pChain: ");
				for (PcodeOp p : pChain) {
					System.out.println(": " +  p);
				}
				return true;
			}
			depChain.clear();
			pChain.clear();
			
		}
		return false;
	}
	
	private Boolean isSelfDependent(PcodeOp currOp, List<Varnode> depChain, List<PcodeOp> pChain, CircularList<PcodeOp> instructions) {
		if(VERBOSE_PRINT) {
			System.out.println("pCodeOp: " + currOp);
		}
		
		pChain.add(currOp);
		if (currOp.getOutput() != null) {
			depChain.add(currOp.getOutput());
		}
		
		// Find the inputs we are looking for
    	Set<Varnode> seen = new HashSet<>();
    	Set<Varnode> inputs = new HashSet<>();
		switch(currOp.getOpcode()) {
		case PcodeOp.STORE:
			inputs.add(currOp.getInput(1));
			break;
		case PcodeOp.INDIRECT:
		case PcodeOp.LOAD:
		case PcodeOp.MULTIEQUAL:
			depChain.remove(currOp.getOutput());
			for (Varnode input : currOp.getInputs()) {
				if(!seen.contains(input)) {
					
					// Check if the input is in the dependency chain
					for (Varnode dv : depChain) {
						if (dv.getSpace() == input.getSpace() && dv.getOffset() == input.getOffset()) {
							if (VERBOSE_PRINT) {
								System.out.println("Self dependent: " + input);
							}
							return true;
						}
					}
					
					inputs.add(input);
				}
				seen.add(input);
			}
			break;
		default:
			for (Varnode input : currOp.getInputs()) {
				if(!seen.contains(input)) {
					
					// Check if the input is in the dependency chain
					for (Varnode dv : depChain) {
						if (dv.getSpace() == input.getSpace() && dv.getOffset() == input.getOffset()) {
							if (VERBOSE_PRINT) {
								System.out.println("Self dependent: " + input);
							}
							return true;
						}
					}
					
					inputs.add(input);
				}
				seen.add(input);
			}
			break;
        }
		
		instructions.setIndex(currOp);
		PcodeOp prevOp = instructions.previous();
		while (prevOp != currOp) {
			for (Varnode input : inputs) {
				if (prevOp.getOutput() != null && prevOp.getOutput().getSpace() == input.getSpace()
						&& prevOp.getOutput().getOffset() == input.getOffset()) {
					if (isSelfDependent(prevOp, depChain, pChain, instructions)) {
						return true;
					}
				}
			}
			prevOp = instructions.previous();
		}
		
		depChain.remove(currOp.getOutput());
		pChain.remove(currOp);
		return false;
	}

}
