package util;

import analyze.Global;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.List;

/**
 * SymbolUtil provides utility methods for interacting with symbols and functions in a Ghidra program.
 */
public class SymbolUtil {

    /**
     * Retrieves a list of symbols with the given name.
     *
     * @param symName The name of the symbol to search for.
     * @return A list of symbols with the specified name.
     */
    public static List<Symbol> getSymbolWithName(String symName) {
        Program program = Global.getProgram();
        SymbolTable symTable = program.getSymbolTable();
        SymbolIterator symbolIterator = symTable.getSymbols(symName);
        List<Symbol> res = new ArrayList<>();
        while (symbolIterator.hasNext()) {
            res.add(symbolIterator.next());
        }
        return res;
    }

    /**
     * Retrieves the symbol located at a specific address.
     *
     * @param addr The address of the symbol to retrieve.
     * @return The symbol at the specified address.
     */
    public static Symbol getSymbolAt(long addr) {
        Program program = Global.getProgram();
        SymbolTable symTable = program.getSymbolTable();
        return symTable.getSymbol(addr);
    }

    /**
     * Parses a virtual table to retrieve a list of functions.
     * Assumes the virtual table starts at the symbol address and each entry is a pointer to a function.
     *
     * @param vtable The symbol representing the virtual table.
     * @return A list of functions found in the virtual table.
     */
    public static List<Function> parseVirtualTable(Symbol vtable) {
        List<Function> table = new ArrayList<>();
        Program program = Global.getProgram();

        Address currentAddr = vtable.getAddress();
        currentAddr = currentAddr.add(Global.POINTER_SIZE * 2); // Skip starting zeros
        Data data;
        while (true) {
            data = program.getListing().getDataAt(currentAddr);
            DataType type = data.getDataType();
            if (!type.getName().equals("pointer")) // Loop until vtable ends
                break;
            Address dataAddr = (Address) data.getValue();
            Function f = FunctionUtil.getFunctionWith(program, dataAddr);
            table.add(f);
            currentAddr = currentAddr.add(program.getDefaultPointerSize());
        }
        return table;
    }

    /**
     * Validates if the given string is a valid path in the format of /dev/...
     *
     * @param str The string to validate.
     * @return True if the string is a valid path, false otherwise.
     */
    public static boolean isValidPath(String str) {
        String REGEX = "^/dev/([^/ ]*)+(/[^/ ]*)*?$";
        return str.matches(REGEX);
    }
}
