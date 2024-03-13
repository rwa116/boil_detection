package boil_detection_project;

import ghidra.program.model.listing.Instruction;

import java.util.List;
import java.util.ArrayList;

public class Helper {
	
	static String getInstructionString(Instruction instruction) {
		return instruction.getMnemonicString();
	}
	
	static List<String> getInstructionOperands(Instruction instruction) {
		List<String> operands = new ArrayList<>();
		operands.add(instruction.getDefaultOperandRepresentation(0));
		operands.add(instruction.getDefaultOperandRepresentation(1));
		return operands;
	}
}
