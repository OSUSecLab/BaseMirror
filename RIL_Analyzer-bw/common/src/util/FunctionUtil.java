package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TimeoutTaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import analyze.Config;

/**
 * FunctionUtil provides utility methods for working with functions in a Ghidra Program.
 */
public class FunctionUtil {

    // Timeout for disassembling functions
    public static long DISASSEMBLE_TIMEOUT = 3000;
    
    // Cached list of functions
    public static List<Function> functions;

    /**
     * Retrieves all functions in the given program. If the functions are already cached,
     * returns the cached list.
     *
     * @param program The Ghidra Program from which functions are retrieved.
     * @return A list of all functions in the program.
     */
    public static List<Function> getAllFunctions(Program program) {
        if (functions != null)
            return functions;

        functions = new ArrayList<>();
        // Load all functions if not done
        FunctionIterator funcIt = program.getFunctionManager().getFunctions(program.getMinAddress(), true);

        for (Function extfun : funcIt) {
            functions.add(extfun);
        }

        return functions;
    }

    /**
     * Extracts the class name from a function name by removing the "<EXTERNAL>::" prefix
     * and splitting the name by "::".
     *
     * @param name The function name.
     * @return The class name or null if not found.
     */
    public static String getClassFromFuncName(String name) {
        name = name.replace("<EXTERNAL>::", "");
        if (name.contains("::")) {
            String[] tokens = name.split("::");
            int lastIndex = tokens.length - 1;
            return tokens[lastIndex - 1];
        } else {
            return null;
        }
    }

    /**
     * Finds a function by its name. If the function name includes parameters, they are removed
     * before searching. If multiple functions match, the one with a thunked function is returned.
     *
     * @param program The Ghidra Program to search in.
     * @param funcName The name of the function to find.
     * @return The matching function or null if not found.
     */
    public static Function getFunctionWithName(Program program, String funcName) {

        // Remove parameters
        if (funcName.contains("("))
            funcName = funcName.substring(0, funcName.indexOf("("));

        List<Function> candidates = new ArrayList<>();

        for (Function function: getAllFunctions(program)) {
            if (function.toString().equals(funcName))
                candidates.add(function);
        }

        if (candidates.size() == 0)
            return null;
        else if (candidates.size() == 1)
            return candidates.get(0);
        else {
            // Multiple candidates
            for (Function f: candidates) {
                if (candidates.contains(f.getThunkedFunction(true)))
                    return f;
            }
            return candidates.get(0);
        }
    }

    /**
     * Retrieves all functions located in the "EXTERNAL" memory block.
     *
     * @param program The Ghidra Program to search in.
     * @return A list of external functions.
     */
    public static List<Function> getAllExternalFunctions(Program program) {

        MemoryBlock[] blocks = program.getMemory().getBlocks();
        MemoryBlock external = null;
        for (MemoryBlock block : blocks) {
            if (block.getName().equals("EXTERNAL")) {
                external = block;
                break;
            }
        }

        List<Function> externalFunc = new ArrayList<>();

        if (external == null)
            return externalFunc;

        for (Function fun: program.getFunctionManager().getFunctions(true)) {
            if (external.contains(fun.getEntryPoint()))
                externalFunc.add(fun);
        }

        return externalFunc;
    }

    /**
     * Constructs the signature of a function, including its name, return type, and parameters.
     *
     * @param f The function to get the signature for.
     * @return The function's signature as a string.
     */
    public static String getFunctionSignature(Function f) {
        StringBuilder signature = new StringBuilder();
        String name = f.toString();
        String returnType = f.getReturnType().toString();
        StringBuilder params = new StringBuilder();

        for (Parameter p: f.getParameters()) {
            if (p.getDataType().toString().contains("\n")) {
                // Special case for types with new lines
                try {
                    params.append(p.toString().split(" ")[0].substring(1));
                    params.append("*");
                } catch (Exception e) {
                    // Handle exception (e.g., malformed parameter)
                }
            } else {
                params.append(p.getDataType().toString().replace(" ", ""));
            }
            params.append(",");
        }

        if (params.length() > 0)
            params.deleteCharAt(params.length()-1); // Remove the last comma

        name = name.replace("<EXTERNAL>::", "");
        name = name.replace("\n", "");
        signature.append(name);
        signature.append("(");
        signature.append(params);
        signature.append(")");

        return signature.toString();
    }

    /**
     * Retrieves the function that contains the specified address.
     *
     * @param program The Ghidra Program to search in.
     * @param address The address to find the containing function for.
     * @return The function containing the address or null if not found.
     */
    public static Function getFunctionWith(Program program, Address address) {
        if (address == null)
            return null;
        return program.getFunctionManager().getFunctionContaining(address);
    }

    /**
     * Retrieves all functions that call the specified function.
     *
     * @param function The function to find callers for.
     * @return A set of functions that call the specified function.
     */
    public static Set<Function> getCallingFunction(Function function) {
        try {
            return function.getCallingFunctions(TimeoutTaskMonitor.timeoutIn(500, TimeUnit.SECONDS));
        } catch (NullPointerException e) {
            return null;
        }
    }

    /**
     * Locates functions in the program whose signature matches the specified signature.
     * Can search for exact or partial matches.
     *
     * @param program The Ghidra Program to search in.
     * @param signature The function signature to search for.
     * @param exactlyEqual If true, search for exact matches; otherwise, search for partial matches.
     * @return A list of addresses of functions matching the signature.
     */
    public static List<Address> locateFunctionWithSig(Program program, String signature, boolean exactlyEqual) {
        List<Address> results = new ArrayList<>();
        for (Function f: program.getFunctionManager().getFunctions(true)) {
            Function thunkedFunc = f.getThunkedFunction(true);
            if (thunkedFunc != null)
                f = thunkedFunc;
            if (exactlyEqual) {
                if (getFunctionSignature(f).equals(signature) || (thunkedFunc != null && getFunctionSignature(thunkedFunc).equals(signature))) {
                    if (!results.contains(f.getEntryPoint()))
                        results.add(f.getEntryPoint());
                }
            } else {
                if (getFunctionSignature(f).contains(signature) || (thunkedFunc != null && getFunctionSignature(thunkedFunc).contains(signature))) {
                    if (!results.contains(f.getEntryPoint()))
                        results.add(f.getEntryPoint());
                }
            }
        }

        return results;
    }

    /**
     * Retrieves functions that are not called by any other functions.
     *
     * @param program The Ghidra Program to search in.
     * @return A list of functions without callers.
     */
    public static List<Function> getFunctionWithoutCaller(Program program) {
        List<Function> results = new ArrayList<>();
        for (Function f: program.getFunctionManager().getFunctions(true)) {
            try {
                if (f.getCallingFunctions(TimeoutTaskMonitor.timeoutIn(500, TimeUnit.SECONDS)).size() == 0)
                    results.add(f);
            } catch (NullPointerException e) {
                results.add(f);
            }
        }
        return results;
    }

    /**
     * Recursively retrieves all functions called by the specified function.
     *
     * @param function The function to find called functions for.
     * @param res The set to add the found functions to.
     */
    public static void recursiveGetCalledFunc(Function function, Set<Function> res) {
        if (function == null)
            return;

        Set<Function> calledFunctions = function.getCalledFunctions(TimeoutTaskMonitor.timeoutIn(DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

        if (calledFunctions == null)
            return;

        for (Function des: calledFunctions) {
            if (!res.contains(des)) {
                res.add(des);
                recursiveGetCalledFunc(des, res);
            }
        }
    }

    /**
     * Recursively retrieves all functions that call the specified function.
     *
     * @param function The function to find calling functions for.
     * @param res The set to add the found functions to.
     */
    public static void recursiveGetCallingFunc(Function function, Set<Function> res) {
        if (function == null)
            return;

        Set<Function> callingFunc = function.getCallingFunctions(TimeoutTaskMonitor.timeoutIn(DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

        if (callingFunc == null)
            return;

        for (Function des: callingFunc) {
            if (!res.contains(des)) {
                res.add(des);
                recursiveGetCallingFunc(des, res);
            }
        }
    }

    /**
     * Determines if a function is a constructor based on its name and thunked function.
     *
     * @param func The function to check.
     * @return True if the function is a constructor, false otherwise.
     */
    public static boolean isConstructor(Function func) {
        if (func == null)
            return false;

        if (!func.toString().contains("::")) {
            if (func.getThunkedFunction(true) != null) {
                func = func.getThunkedFunction(true); // Handle thunked function
                if (!func.toString().contains("::"))
                    return false;
            } else {
                return false;
            }
        }

        String[] tokens = func.toString().split("::");
        int lastIndex = tokens.length - 1;
        int lastButTwo = lastIndex - 1;

        return tokens[lastIndex].equals(tokens[lastButTwo]);
    }

    /**
     * Retrieves the constructor function that is called by the specified function.
     *
     * @param program The Ghidra Program to search in.
     * @param func The function to find the parent constructor for.
     * @return The parent constructor function or null if not found.
     */
    public static Function getParentConstructor(Program program, Function func) {
        ReferenceManager referenceManager = program.getReferenceManager();

        for (Address add: func.getBody().getAddresses(true)) {
            Reference[] references = referenceManager.getReferencesFrom(add);
            for (Reference ref: references) {
                Function targetFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (targetFunc != null) {
                    if (FunctionUtil.isConstructor(targetFunc)) {
                        // Return the first constructor that gets called
                        if (targetFunc.getThunkedFunction(true) != null)
                            return targetFunc.getThunkedFunction(true);
                        else
                            return targetFunc;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Finds the constructor function for a given class name.
     *
     * @param program The Ghidra Program to search in.
     * @param className The name of the class to find the constructor for.
     * @return The constructor function or null if not found.
     */
    public static Function getConstructorFunction(Program program, String className) {
        String constructorName = className + "::" + className;
        return getFunctionWithName(program, constructorName);
    }

    /**
     * Checks if the given string contains any of the keywords defined in the configuration.
     *
     * @param str The string to check.
     * @return True if any of the keywords are found, false otherwise.
     */
    public static boolean havePriKeyword(String str){
        for(String keyword : Config.PRI_KEYWORDS){
            if(str.toLowerCase().contains(keyword)){
                return true;
            }
        }
        return false;
    }
}
