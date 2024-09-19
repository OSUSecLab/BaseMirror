package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * VCallUtil provides utility methods for managing and retrieving virtual function calls and their associated data.
 */
public class VCallUtil {
    // Maps class names to their virtual table symbols.
    public static Map<String, Symbol> vtable = new HashMap<>();
    
    // Maps callee addresses to a list of caller addresses.
    public static Map<Address, List<Address>> vCalls = new HashMap<>();
    
    // Maps class names to a map of expressions to inferred types.
    public static Map<String, Map<String, List<String>>> vTypes = new HashMap<>();

    /**
     * Retrieves the virtual table symbol for the given class name.
     *
     * @param className The name of the class for which to retrieve the virtual table.
     * @return The symbol representing the virtual table for the specified class.
     */
    public static Symbol getVTable(String className) {
        return vtable.get(className);
    }

    /**
     * Checks if a virtual table exists for the given class name.
     *
     * @param className The name of the class to check.
     * @return True if a virtual table exists for the specified class, false otherwise.
     */
    public static boolean containVTable(String className) {
        return vtable.containsKey(className);
    }

    /**
     * Adds a virtual table symbol for a given class name.
     *
     * @param className The name of the class.
     * @param symbol    The symbol representing the virtual table.
     */
    public static void addVTable(String className, Symbol symbol) {
        vtable.put(className, symbol);
    }

    /**
     * Adds a virtual function call mapping.
     * Maps a callee address to a list of caller addresses.
     *
     * @param key   The address of the callee.
     * @param value The address of the caller.
     */
    public static void addVCall(Address key, Address value) {
        if (vCalls.containsKey(key)) {
            vCalls.get(key).add(value);
        } else {
            List<Address> lst = new ArrayList<>();
            lst.add(value);
            vCalls.put(key, lst);
        }
    }

    /**
     * Adds or updates the inferred type for a given class and expression.
     *
     * @param className The name of the class.
     * @param exp       The expression related to the type.
     * @param type      The inferred type.
     */
    public static void addVType(String className, String exp, String type) {
        if (type == null) {
            type = "";
        }
        if (vTypes.containsKey(className)) {
            if (vTypes.get(className).containsKey(exp)) {
                if (vTypes.get(className).get(exp).contains(type)) {
                    return; // Type already exists for this expression
                } else {
                    vTypes.get(className).get(exp).add(type);
                }
            } else {
                RILLog.debugLog("VType add " + className + " " + exp + " " + type);
                List<String> tmp = new ArrayList<>();
                tmp.add(type);
                vTypes.get(className).put(exp, tmp);
            }
        } else {
            RILLog.debugLog("VType add " + className + " " + exp + " " + type);
            Map<String, List<String>> tmp = new HashMap<>();
            List<String> tmpList = new ArrayList<>();
            tmpList.add(type);
            tmp.put(exp, tmpList);
            vTypes.put(className, tmp);
        }
    }

    /**
     * Retrieves the list of inferred types for a given class and expression.
     *
     * @param className The name of the class.
     * @param exp       The expression related to the types.
     * @return A list of inferred types for the given class and expression, or null if no types are found.
     */
    public static List<String> getVType(String className, String exp) {
        RILLog.debugLog("VType Cache hit " + className + " " + exp);
        if (vTypes.containsKey(className) && vTypes.get(className).containsKey(exp)) {
            return vTypes.get(className).get(exp);
        } else {
            return null;
        }
    }

    /**
     * Retrieves the list of caller addresses for a given callee address.
     *
     * @param addr The address of the callee.
     * @return A list of addresses that call the specified callee, or null if no callers are found.
     */
    public static List<Address> getVCaller(Address addr) {
        return vCalls.get(addr);
    }
}
