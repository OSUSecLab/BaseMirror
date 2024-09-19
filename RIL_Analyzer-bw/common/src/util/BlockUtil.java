package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

/**
 * BlockUtil provides utility methods for handling and analyzing code blocks in a Ghidra program.
 */
public class BlockUtil {

    // Cached memory blocks for external and plt sections
    public static MemoryBlock external = null;
    public static MemoryBlock plt = null;

    /**
     * Locates the code blocks that contain a specific address.
     *
     * @param program The program to search within.
     * @param address The address to locate in code blocks.
     * @return An array of code blocks containing the specified address, or null if the operation is cancelled.
     */
    public static CodeBlock[] locateBlockWithAddress(Program program, Address address) {
        BasicBlockModel basicBlockModel = new BasicBlockModel(program);
        try {
            CodeBlock[] codeBlocks = basicBlockModel.getCodeBlocksContaining(address, TaskMonitor.DUMMY);
            return codeBlocks;
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Gets the parent blocks (predecessors) of the specified code block.
     *
     * @param codeBlock The code block whose parent blocks are to be retrieved.
     * @return A list of code block references to the parent blocks, or null if the operation is cancelled.
     */
    public static List<CodeBlockReference> getPreviousBlocks(CodeBlock codeBlock) {
        List<CodeBlockReference> result = new ArrayList<>();
        try {
            CodeBlockReferenceIterator codeBlockReferenceSourcesIterator = codeBlock.getSources(TaskMonitor.DUMMY);
            while (codeBlockReferenceSourcesIterator.hasNext()) {
                CodeBlockReference codeBlockReference = codeBlockReferenceSourcesIterator.next();
                result.add(codeBlockReference);
            }
            return result;
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Gets the descendant blocks (successors) of the specified code block.
     *
     * @param codeBlock The code block whose descendant blocks are to be retrieved.
     * @return A list of code block references to the descendant blocks, or null if the operation is cancelled.
     */
    public static List<CodeBlockReference> getDescentdentBlocks(CodeBlock codeBlock) {
        List<CodeBlockReference> result = new ArrayList<>();
        try {
            CodeBlockReferenceIterator codeBlockReferenceDestsIterator = codeBlock.getDestinations(TaskMonitor.DUMMY);
            while (codeBlockReferenceDestsIterator.hasNext()) {
                CodeBlockReference codeBlockReference = codeBlockReferenceDestsIterator.next();
                result.add(codeBlockReference);
            }
            return result;
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Checks if the given code block is in the external memory block.
     *
     * @param program The program containing the memory blocks.
     * @param block The code block to check.
     * @return True if the block is in the external memory block, false otherwise.
     */
    public static boolean isExternalBlock(Program program, CodeBlock block) {

        // Lazy initialization of external memory block
        if (external == null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock b : blocks) {
                if (b.getName().equals("EXTERNAL")) {
                    external = b;
                    break;
                }
            }
        }

        Address add = block.getFirstStartAddress();

        // Special case for a specific address
        if (add.toString().equals("ffff0fc0"))
            return true;

        return external.contains(add);
    }

    /**
     * Checks if the given address is in the external memory block.
     *
     * @param program The program containing the memory blocks.
     * @param address The address to check.
     * @return True if the address is in the external memory block, false otherwise.
     */
    public static boolean isExternalAddress(Program program, Address address) {

        // Lazy initialization of external memory block
        if (external == null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock b : blocks) {
                if (b.getName().equals("EXTERNAL")) {
                    external = b;
                    break;
                }
            }
        }

        // Special case for a specific address
        if (address.toString().equals("ffff0fc0"))
            return true;

        return external.contains(address);
    }

    /**
     * Checks if the given code block is in the plt (Procedure Linkage Table) memory block.
     *
     * @param program The program containing the memory blocks.
     * @param block The code block to check.
     * @return True if the block is in the plt memory block, false otherwise.
     */
    public static boolean isPltBlock(Program program, CodeBlock block) {
        if (plt == null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock b : blocks) {
                if (b.getName().equals(".plt")) {
                    plt = b;
                    break;
                }
            }
        }

        Address add = block.getFirstStartAddress();
        return plt.contains(add);
    }

    /**
     * Checks if the given address is in the plt (Procedure Linkage Table) memory block.
     *
     * @param program The program containing the memory blocks.
     * @param address The address to check.
     * @return True if the address is in the plt memory block, false otherwise.
     */
    public static boolean isPltAddress(Program program, Address address) {
        if (plt == null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock b : blocks) {
                if (b.getName().equals(".PLT")) {
                    plt = b;
                    break;
                }
            }
        }

        return plt.contains(address);
    }
}
