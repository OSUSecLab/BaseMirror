package util;

import analyze.Config;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TimeoutTaskMonitor;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Decompiler provides utility methods to decompile functions in a Ghidra program
 * and cache the decompilation results to improve performance.
 */
public class Decompiler {

    // Singleton instance of DecompInterface for decompiling functions
    private static DecompInterface ifc;

    // Cache for decompile results to avoid redundant decompilation
    public static Map<Long, DecompileResults> decompilerCache = new HashMap<>();

    /**
     * Initializes the decompilation interface if it has not been initialized yet.
     */
    private static void initIfc () {
        if (ifc == null) {
            decompilerCache = new HashMap<>();
            DecompileOptions options = new DecompileOptions();
            ifc = new DecompInterface();
            ifc.setOptions(options);
        }
    }

    /**
     * Decompiles the given function in the specified program using the given decompile mode.
     * Results are cached to improve performance if caching is enabled.
     *
     * @param program The program containing the function to decompile.
     * @param decompileMode The decompilation mode to use.
     * @param function The function to decompile.
     * @return The decompile results, or null if the decompilation fails or the function is external.
     */
    private static DecompileResults decompile(Program program, String decompileMode, Function function) {

        initIfc(); // Initialize the decompilation interface if needed

        if (function == null)
            return null;

        if (function.isExternal()) // Do not decompile external functions
            return null;

        if (!ifc.openProgram(program)) {
            // Failed to open the program for decompilation
            return null;
        }

        // Check if the result is already in the cache
        if (Config.DECOMPILER_CACHE) {
            if (decompilerCache.containsKey(function.getEntryPoint().getUnsignedOffset()))
                return decompilerCache.get(function.getEntryPoint().getUnsignedOffset());
        }

        // Set decompile options and perform the decompilation
        ifc.setSimplificationStyle(decompileMode);
        DecompileResults res = ifc.decompileFunction(function, Config.DECOMPILE_TIMEOUT, TimeoutTaskMonitor.timeoutIn(Config.DECOMPILE_TIMEOUT, TimeUnit.SECONDS));
        if (res == null || !res.decompileCompleted()) {
            // Decompilation failed
            ifc.closeProgram();
            return null;
        } else {
            // Cache the decompile result if caching is enabled
            if (Config.DECOMPILER_CACHE) {
                cacheDecompileResult(function.getEntryPoint().getUnsignedOffset(), res);
            }
            ifc.closeProgram();
            return res;
        }
    }

    /**
     * Caches the decompilation result for a given function address.
     *
     * @param address The address of the function to cache.
     * @param res The decompile results to cache.
     */
    public static void cacheDecompileResult(long address, DecompileResults res) {
        if (!decompilerCache.containsKey(address))
            decompilerCache.put(address, res);
    }

    /**
     * Decompiles the given function using the default decompile mode specified in the configuration.
     *
     * @param program The program containing the function to decompile.
     * @param function The function to decompile.
     * @return The decompile results, or null if the decompilation fails or the function is external.
     */
    public static DecompileResults decompileFunc(Program program, Function function) {
        return decompile(program, Config.DECOMPILE_MODE, function);
    }

    /**
     * Decompiles the given function using the "normalize" decompile mode.
     * This mode is used for solving function call parameters.
     *
     * @param program The program containing the function to decompile.
     * @param function The function to decompile.
     * @return The decompile results, or null if the decompilation fails or the function is external.
     */
    public static DecompileResults decompileFuncNormalize(Program program, Function function) {
        return decompile(program, "normalize", function);
    }

    /**
     * Decompiles the given function using the "register" decompile mode.
     *
     * @param program The program containing the function to decompile.
     * @param function The function to decompile.
     * @return The decompile results, or null if the decompilation fails or the function is external.
     */
    public static DecompileResults decompileFuncRegister(Program program, Function function) {
        return decompile(program, "register", function);
    }
}
