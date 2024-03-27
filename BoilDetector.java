package boil_detection_project;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphFactory;
import ghidra.graph.GraphAlgorithms;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;

public class BoilDetector {
	
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
		List<PcodeOp> instructions = new ArrayList<PcodeOp>();
		Stack<PcodeOp> stores = new Stack<PcodeOp>();
		for (PcodeBlockBasic block : loopBodyCFG.getVertices()) {
			Iterator<PcodeOp> opIt = block.getIterator();
			while (opIt.hasNext()) {
				PcodeOp op = opIt.next();
				if (op.getOpcode() == PcodeOp.STORE) {
					stores.push(op);
				}
				instructions.add(op);
			}
		}
		while (!stores.isEmpty()) {
			List<Varnode> depChain = new ArrayList<Varnode>();
			List<PcodeOp> pChain = new ArrayList<PcodeOp>();
			Set<Instruction> visited = new HashSet<Instruction>();
			PcodeOp store = stores.pop();
			System.out.println("Store: " + store + " memory offset: " + store.getInput(1));
			pChain.add(store);
			if (isSelfDependent(store.getInput(1), depChain, pChain, instructions)) {
				System.out.println("Dep chain: " + depChain);
				System.out.println("Dep pChain: ");
				for (PcodeOp p : pChain) {
					System.out.println(": " +  p);
				}
				return true;
			}
			
		}
		return false;
	}
	
	private Boolean isSelfDependent(Varnode v, List<Varnode> depChain, List<PcodeOp> pChain, List<PcodeOp> instructions) {
		if (depChain.contains(v)) {
			return true;
		}
		
		depChain.add(v);
		PcodeOp def = v.getDef();
		pChain.add(def);
	    if(def != null && instructions.contains(def)) {
			switch(def.getOpcode()) {
			case PcodeOp.STORE:
				if (isSelfDependent(def.getInput(1), depChain, pChain, instructions)) {
					return true;
				}
				break;
			default:
				for(Varnode input : def.getInputs()) {
                    if (isSelfDependent(input, depChain, pChain, instructions)) {
                        return true;
                    }
                }
				break;
            }
        
		}
	    
	    pChain.remove(def);
	    depChain.remove(v);
            
		
		return false;
	}

}
