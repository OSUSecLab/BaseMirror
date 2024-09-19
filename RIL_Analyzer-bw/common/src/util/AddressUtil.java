package util;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.Iterator;
import java.util.List;

/**
 * AddressUtil provides utility methods for handling and analyzing addresses in a Ghidra program.
 */
public class AddressUtil {

    /**
     * Converts a long value to a Ghidra address.
     *
     * @param program The program containing the address.
     * @param val The long value to convert.
     * @return The address corresponding to the long value.
     */
    public static Address getAddressFromLong(Program program, long val) {
        return program.getAddressFactory().getAddress(NumericUtil.longToHexString(val));
    }

    /**
     * Retrieves an iterator of references to a specific address.
     *
     * @param program The program to search within.
     * @param address The address to find references to.
     * @return An iterator of references to the specified address.
     */
    public static ReferenceIterator getReferenceToAddress(Program program, Address address) {
        ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(address);
        return iterator;
    }

    /**
     * Counts the number of references to a specific address.
     *
     * @param program The program to search within.
     * @param address The address to count references to.
     * @return The count of references to the specified address.
     */
    public static int getReferenceCount(Program program, Address address) {
        return program.getReferenceManager().getReferenceCountTo(address);
    }

    /**
     * Finds an address that is connected to a given address through function calls.
     *
     * @param program The program to search within.
     * @param address The starting address to search from.
     * @param allConnectAdd A list of addresses to look for connections to.
     * @return The address that is connected to the given address, or null if no connection is found.
     */
    public static Address findConnectionAddress(Program program, Address address, List<Address> allConnectAdd) {
        Function currentFunc = FunctionUtil.getFunctionWith(program, address);
        if (currentFunc == null)
            return null;

        DecompileResults results = Decompiler.decompileFuncRegister(program, currentFunc);
        if (results == null)
            return null;

        HighFunction highFunction = results.getHighFunction();
        Address current = address;
        while (current.next() != null) {
            Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps(current);
            while (pcodeOpASTIterator.hasNext()) {
                PcodeOpAST ast = pcodeOpASTIterator.next();
                String mnem = ast.getMnemonic();
                if (mnem.equals("CALL")) {
                    Varnode inputNode = ast.getInputs()[0];
                    Address callAdd = inputNode.getAddress();
                    if (allConnectAdd.contains(callAdd))
                        return current;
                }
            }
            current = current.next();
            if (currentFunc.getBody().getMaxAddress().getUnsignedOffset() <= current.getUnsignedOffset())
                return null;
        }
        return null;
    }

    /**
     * Retrieves the address of the next instruction after the given address.
     *
     * @param program The program containing the instructions.
     * @param current The current address.
     * @return The address of the next instruction.
     */
    public static Address getAddressInNextIns(Program program, Address current) {
        Instruction currentIns = program.getListing().getInstructionAt(current);
        Address next = current;
        Instruction nextIns = null;
        do {
            next = next.next();
            nextIns = program.getListing().getInstructionAt(next);
        } while (nextIns == null);

        return next;
    }
}
