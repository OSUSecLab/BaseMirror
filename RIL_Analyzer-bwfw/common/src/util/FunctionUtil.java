package util;

import analyze.Config;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TimeoutTaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class FunctionUtil {

    public static long DISASSEMBLE_TIMEOUT = 3000;
    public static List<Function> functions;
    public static List<Address> addrGetRxDatas;


    public static List<Function> getAllFunctions(Program program) {
        if (functions != null)
            return functions;

        functions = new ArrayList<>();
        addrGetRxDatas = new ArrayList<>();
        // load all function if not done
        FunctionIterator funcIt = program.getFunctionManager().getFunctions(program.getMinAddress(), true);

        for (Function extfun : funcIt) {
            functions.add(extfun);
            if(extfun.getName().equals("GetRxData") && !extfun.getParentNamespace().isGlobal()){
                addrGetRxDatas.add(extfun.getEntryPoint());
            }
        }

        return functions;
    }

    public static String getClassFromFuncName(String name) {
        name = name.replace("<EXTERNAL>::", "");
        if (name.contains("::")) {
            String[] tokens = name.split("::");
            int lastIndex = tokens.length - 1;
            return tokens[lastIndex - 1];
        }
        else
            return null;
    }

    public static Function getFunctionWithName(Program program, String funcName) {

        // remove parameters
        if (funcName.contains("("))
            funcName = funcName.substring(0, funcName.indexOf("("));

        List<Function> candidates = new ArrayList<>();

        Namespace namespace = null;
        SymbolTable symbolTable = program.getSymbolTable();
        if(funcName.contains("::")){ // class member function
            namespace = symbolTable.getNamespace(funcName.split("::")[0], program.getGlobalNamespace());
        }
        if(namespace == null){// global function
            namespace = program.getGlobalNamespace();
        }

        try {
            FunctionIterator functionIterator = program.getFunctionManager().getFunctions(namespace.getBody(), true);
            while(functionIterator.hasNext()){
                Function function = functionIterator.next();
                if(function.toString().equals(funcName)){
                    candidates.add(function);
                }
            }
        }catch (NullPointerException e){
            e.printStackTrace();
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

    public static Function getWrapperFunctionWithName(Program program, String funcName) {
        Function func = getFunctionWithName(program, funcName);
        ReferenceIterator referenceIterator = AddressUtil.getReferenceToAddress(program, func.getEntryPoint());
        while(referenceIterator.hasNext()){
            Reference reference = referenceIterator.next();
            Address address = reference.getFromAddress();
            Function wrapper = FunctionUtil.getFunctionWith(program, address);
            if(wrapper != null && wrapper.getThunkedFunction(true).equals(func)){
                return wrapper;
            }
        }
        return func;
    }

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


    public static String getFunctionSignature(Function f) {
        StringBuilder signature = new StringBuilder();
        String name = f.toString();
        String returnType = f.getReturnType().toString();
        StringBuilder params = new StringBuilder();

        for (Parameter p: f.getParameters()) {
            if (p.getDataType().toString().contains("\n")) {
                // special case
                try {
                    params.append(p.toString().split(" ")[0].substring(1));
                    params.append("*");
                } catch (Exception e) {

                }
            }
            else {
                params.append(p.getDataType().toString().replace(" ", ""));
            }
            params.append(",");

        }

        if (params.length() > 0)
            params.deleteCharAt(params.length()-1); // remove the last comma

        name = name.replace("<EXTERNAL>::", "");
        name = name.replace("\n", "");
        signature.append(name);
        signature.append("(");
        signature.append(params);
        signature.append(")");

        return signature.toString();
    }


    public static Function getFunctionWith(Program program, Address address) {
        if (address == null)
            return null;
        return program.getFunctionManager().getFunctionContaining(address);
    }

    /**
     * Retrieves a set of functions that call the specified function.
     * 
     * @param function The function to get callers for.
     * @return A set of functions that call the specified function, or null if an error occurs.
     */
    public static Set<Function> getCallingFunction(Function function) {
        try {
            return function.getCallingFunctions(TimeoutTaskMonitor.timeoutIn(500, TimeUnit.SECONDS));
        } catch (NullPointerException e) {
            return null;
        }
    }

    /**
     * Locates functions with a signature matching the specified string.
     * 
     * @param program The program to search within.
     * @param signature The function signature to match.
     * @param exactlyEqual If true, only exact matches are considered; otherwise, partial matches are allowed.
     * @return A list of addresses where functions matching the signature are located.
     */
    public static List<Address> locateFunctionWithSig(Program program, String signature, boolean exactlyEqual) {
        List<Address> results = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
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
     * Retrieves functions that do not have any callers.
     * 
     * @param program The program to search within.
     * @return A list of functions that are not called by any other functions.
     */
    public static List<Function> getFunctionWithoutCaller(Program program) {
        List<Function> results = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
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
     * @param function The function to start the search from.
     * @param res A set to collect the called functions.
     */
    public static void recursiveGetCalledFunc(Function function, Set<Function> res) {

        if (function == null)
            return;

        Set<Function> calledFunctions = function.getCalledFunctions(TimeoutTaskMonitor.timeoutIn(DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

        if (calledFunctions == null)
            return;

        for (Function des : calledFunctions) {
            if (!res.contains(des)) {
                res.add(des);
                recursiveGetCalledFunc(des, res);
            }
        }
    }

    /**
     * Recursively retrieves all functions that call the specified function.
     * 
     * @param function The function to start the search from.
     * @param res A set to collect the calling functions.
     */
    public static void recursiveGetCallingFunc(Function function, Set<Function> res) {

        if (function == null)
            return;

        Set<Function> callingFunc = function.getCallingFunctions(TimeoutTaskMonitor.timeoutIn(DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

        if (callingFunc == null)
            return;

        for (Function des : callingFunc) {
            if (!res.contains(des)) {
                res.add(des);
                recursiveGetCallingFunc(des, res);
            }
        }
    }

    /**
     * Checks if the specified function is a constructor.
     * 
     * @param func The function to check.
     * @return True if the function is a constructor, otherwise false.
     */
    public static boolean isConstructor(Function func) {
        if (func == null)
            return false;

        if (!func.toString().contains("::")) {
            if (func.getThunkedFunction(true) != null) {
                func = func.getThunkedFunction(true); // Handle thunked function
                if (!func.toString().contains("::"))
                    return false;
            } else
                return false;
        }

        String[] tokens = func.toString().split("::");
        int lastIndex = tokens.length - 1;
        int lastButTwo = lastIndex - 1;

        return tokens[lastIndex].equals(tokens[lastButTwo]);
    }

    /**
     * Retrieves the parent constructor function of the specified function.
     * 
     * @param program The program to search within.
     * @param func The function to find the parent constructor for.
     * @return The first constructor function that the specified function calls, or null if none found.
     */
    public static Function getParentConstructor(Program program, Function func) {
        ReferenceManager referenceManager = program.getReferenceManager();

        for (Address add : func.getBody().getAddresses(true)) {
            Reference[] references = referenceManager.getReferencesFrom(add);
            for (Reference ref : references) {
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
     * Retrieves the constructor function for a class given the class name.
     * 
     * @param program The program to search within.
     * @param className The name of the class to find the constructor for.
     * @return The constructor function for the specified class, or null if not found.
     */
    public static Function getConstructorFunction(Program program, String className) {
        String constructorName = className + "::" + className;
        return getFunctionWithName(program, constructorName);
    }

    /**
     * Checks if the specified string contains any of the private keywords defined in the configuration.
     * 
     * @param str The string to check.
     * @return True if the string contains any private keyword, otherwise false.
     */
    public static boolean havePriKeyword(String str) {
        for (String keyword : Config.PRI_KEYWORDS) {
            if (str.toLowerCase().contains(keyword)) {
                return true;
            }
        }
        return false;
    }
}
