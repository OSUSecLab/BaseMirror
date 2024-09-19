package analyze;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.HashMap;
import java.util.Map;
import util.Decompiler;

public class Global {

    // The current program being analyzed.
    public static Program program;

    // Tag for identifying the current analysis context.
    public static String tag;

    // Name associated with the RIL (Radio Interface Layer).
    public static String rilName;

    // P-Code related properties.
    public static int POINTER_SIZE; // Size of pointers in the P-Code.
    public static String LANGUAGE; // Programming language used in the program.
    public static String STACK_REG; // Stack register information.

    /**
     * Returns the current program being analyzed.
     * 
     * @return The current Program instance.
     */
    public static Program getProgram() {
        return program;
    }

    // Cache for storing decompilation results to avoid redundant decompilations.
    private static Map<Function, DecompileResults> decompFuncs = new HashMap<>();

    /**
     * Retrieves decompilation results for a given function. If the results are not cached, 
     * decompile the function and store the results in the cache.
     * 
     * @param func The function to decompile.
     * @return The decompilation results for the given function.
     */
    public static DecompileResults getDecompFunc(Function func){
        // Check if decompilation results are already cached.
        if(decompFuncs.containsKey(func))
            return decompFuncs.get(func);
        else {
            // Decompile the function and cache the results.
            DecompileResults dr = Decompiler.decompileFunc(Global.getProgram(), func);
            decompFuncs.put(func, dr);
            return dr;
        }
    }
}
