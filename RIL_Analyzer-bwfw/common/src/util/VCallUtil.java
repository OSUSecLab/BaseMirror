package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VCallUtil {
    // Map to store vtables by class name, where the key is the class name and the value is the corresponding Symbol
    public static Map<String, Symbol> vtable = new HashMap<>();
    
    // Map to store virtual function calls with the callee address as the key and a list of caller addresses as the value
    public static Map<Address, List<Address>> vCalls = new HashMap<>();
    
    // Map to store virtual function calls in reverse order, where the key is the caller address and the value is a list of callee addresses
    public static Map<Address, List<Address>> vCallsRev = new HashMap<>();
    
    // Map to store inferred types from virtual call expressions, where the key is the class name, the second key is the expression, and the value is a list of types
    public static Map<String, Map<String, List<String>>> vTypes = new HashMap<>();
    
    // Method to get the vtable for a specific class name
    public static Symbol getVTable(String className) {
        return vtable.get(className);
    }

    // Method to check if the vtable for a specific class name exists
    public static boolean containVTable(String className) {
        return vtable.containsKey(className);
    }

    // Method to add a vtable entry for a specific class name with a Symbol
    public static void addVTable(String className, Symbol symbol) {
        vtable.put(className, symbol);
    }

    // Method to add a virtual function call with the callee address as the key and the caller address as the value
    public static void addVCall(Address key, Address value) {
        if (vCalls.containsKey(key)) {
            vCalls.get(key).add(value);
        } else {
            List<Address> lst = new ArrayList<>();
            lst.add(value);
            vCalls.put(key, lst);
        }
    }

    // Method to add a virtual function call in reverse, with the caller address as the key and the callee address as the value
    public static void addVCallRev(Address key, Address value) {
        if (vCallsRev.containsKey(key)) {
            vCallsRev.get(key).add(value);
        } else {
            List<Address> lst = new ArrayList<>();
            lst.add(value);
            vCallsRev.put(key, lst);
        }
    }

    // Method to get the list of callee addresses for a given caller address
    public static List<Address> getVCallsRevValue(Address key) {
        return vCallsRev.get(key);
    }

    // Method to add an inferred type for a virtual call expression for a specific class name
    public static void addVType(String className, String exp, String type) {
        if (type == null)
            type = "";
        if (vTypes.containsKey(className)) {
            if (vTypes.get(className).containsKey(exp)) {
                if (vTypes.get(className).get(exp).contains(type))
                    return;
                else {
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

    // Method to get the list of inferred types for a virtual call expression for a specific class name
    public static List<String> getVType(String className, String exp) {
        RILLog.debugLog("VType Cache hit " + className + " " + exp);
        if (vTypes.containsKey(className) && vTypes.get(className).containsKey(exp))
            return vTypes.get(className).get(exp);
        else
            return null;
    }

    // Method to get the list of caller addresses for a given callee address
    public static List<Address> getVCaller(Address addr) {
        return vCalls.get(addr);
    }
}
