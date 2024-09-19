package taint;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import util.FunctionUtil;
import util.RILLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import analyze.Global;

/**
 * Represents a taint path used for tracking taint analysis within a program.
 */
public class TaintPath {

    public Integer taintFd; // File descriptor associated with the taint path
    public Function taintFdFunc; // Function associated with the taint path
    public List<Integer> taintArgs; // List of argument indices involved in taint propagation
    public List<PcodeOp> trace; // List of Pcode operations involved in the taint path
    public List<Address> path; // List of addresses involved in the taint path
    public Map<Integer, Long> taintResult; // Taint results stored as long values (e.g., ioctl())
    public Map<Integer, List<Integer>> taintResultFlag; // Flags indicating whether the taint results are static or dynamic
    public Map<Integer, List<Byte>> taintResultByteArray; // Taint results stored as byte arrays (e.g., write())

    /**
     * Default constructor for TaintPath.
     */
    public TaintPath() {

    }

    /**
     * Constructs a TaintPath with specified file descriptor, function, and argument indices.
     * 
     * @param fd The file descriptor associated with the taint path.
     * @param func The function associated with the taint path.
     * @param args The list of argument indices involved in taint propagation.
     */
    public TaintPath(Integer fd, Function func, List<Integer> args) {
        path = new ArrayList<>();
        trace = new ArrayList<>();
        taintFd = fd;
        taintFdFunc = func;
        taintArgs = args;
        taintResult = new HashMap<>();
        taintResultFlag = new HashMap<>();
        taintResultByteArray = new HashMap<>();
    }

    /**
     * Adds an address to the taint path.
     * 
     * @param a The address to add to the taint path.
     */
    public void addToPath(Address a) {
        path.add(a);
    }

    /**
     * Adds a Pcode operation to the trace.
     * 
     * @param p The Pcode operation to add to the trace.
     */
    public void addToTrace(PcodeOp p) {
        trace.add(p);
    }

    /**
     * Checks if the trace contains a specified Pcode operation.
     * 
     * @param p The Pcode operation to check.
     * @return True if the trace contains the Pcode operation, otherwise false.
     */
    public boolean containsTrace(PcodeOp p) {
        for (PcodeOp op : trace) {
            if (p.toString().equals(op.toString()))
                return true;
        }
        return false;
    }

    /**
     * Checks if the path contains a specified address.
     * 
     * @param a The address to check.
     * @return True if the path contains the address, otherwise false.
     */
    public boolean containsPath(Address a) {
        for (Address addr : path) {
            if (addr.getUnsignedOffset() == a.getUnsignedOffset())
                return true;
        }
        return false;
    }

    /**
     * Stores a taint result as a long value.
     * 
     * @param idx The index to associate with the taint result.
     * @param val The taint result value.
     */
    public void putResult(int idx, long val) {
        String TAG = "[TaintPath::putResult] ";
        if (taintResult.containsKey(idx)) {
            RILLog.debugLog(TAG + "complicated result with same idx");
            assert 0 > 1; // Ensure that the index is unique
        }
//        RILLog.debugLog(TAG + "put idx: " + idx + " with value: " + val);
        taintResult.put(idx, val);
    }

    /**
     * Stores a taint result as a byte array and associated flags.
     * 
     * @param idx The index to associate with the taint result.
     * @param array The byte array representing the taint result.
     * @param arrayFlag The flags indicating the nature of the taint result.
     */
    public void putResult(int idx, List<Byte> array, List<Integer> arrayFlag) {
        String TAG = "[TaintPath::putResult] ";
        if (taintResult.containsKey(idx)) {
            RILLog.debugLog(TAG + "duplicated result with same idx");
            assert 0 > 1; // Ensure that the index is unique
        }
//        RILLog.debugLog(TAG + "put idx: " + idx + " with value: " + array);
        taintResultByteArray.put(idx, array);
        taintResultFlag.put(idx, arrayFlag);
    }

    /**
     * Checks if the taint path is empty.
     * 
     * @return True if the taint path is empty, otherwise false.
     */
    public boolean pathEmpty() {
        return path.size() == 0;
    }

    /**
     * Updates the file descriptor associated with the taint path.
     * 
     * @param fd The new file descriptor to set.
     */
    public void updateFd(Integer fd) {
        taintFd = fd;
    }

    /**
     * Updates the function associated with the taint path.
     * 
     * @param func The new function to set.
     */
    public void updateFdFunc(Function func) {
        taintFdFunc = func;
    }

    /**
     * Adds an argument index to the list of taint arguments if it is not already present.
     * 
     * @param idx The argument index to add.
     */
    public void addArgIndex(int idx) {
        if (!taintArgs.contains(idx))
            taintArgs.add(idx);
    }

    /**
     * Removes an argument index from the list of taint arguments.
     * 
     * @param val The argument index to remove.
     */
    public void removeArg(int val) {
        taintArgs.remove(taintArgs.indexOf(val));
    }

    /**
     * Gets the number of taint arguments.
     * 
     * @return The number of taint arguments.
     */
    public int getTaintArgNum() {
        return taintArgs.size();
    }

    /**
     * Retrieves the taint results as long values.
     * 
     * @return A map of taint results indexed by their associated indices.
     */
    public Map<Integer, Long> getResult() {
        return taintResult;
    }

    /**
     * Retrieves the taint results as byte arrays.
     * 
     * @return A map of taint results as byte arrays indexed by their associated indices.
     */
    public Map<Integer, List<Byte>> getResultByteArray() {
        return taintResultByteArray;
    }

    /**
     * Retrieves the flags associated with the taint results.
     * 
     * @return A map of flags indicating the nature of the taint results, indexed by their associated indices.
     */
    public Map<Integer, List<Integer>> getResultFlag() {
        return taintResultFlag;
    }

    /**
     * Checks if there are any taint results.
     * 
     * @return True if there are taint results, otherwise false.
     */
    public boolean hasResult() {
        return taintResult.size() != 0 || taintResultByteArray.size() != 0;
    }

    /**
     * Creates a deep copy of the current TaintPath object.
     * 
     * @return A new TaintPath object with the same values as the current one.
     */
    @Override
    public TaintPath clone() {
        TaintPath p = new TaintPath();
        p.taintFd = this.taintFd;
        p.taintFdFunc = this.taintFdFunc;
        p.taintArgs = new ArrayList<>(this.taintArgs);
        p.path = new ArrayList<>(this.path);
        p.trace = new ArrayList<>(this.trace);
        p.taintResult = new HashMap<>(this.taintResult);
        p.taintResultFlag = new HashMap<>(this.taintResultFlag);
        p.taintResultByteArray = new HashMap<>(this.taintResultByteArray);
        return p;
    }

    /**
     * Converts the trace of Pcode operations to a string representation.
     * 
     * @return A string representation of the Pcode operation trace.
     */
    public String printTrace() {
        StringBuilder s = new StringBuilder();
        for (PcodeOp t : trace) {
            s.append(String.format("%x", t.getParent().getStart().getUnsignedOffset()));
            s.append(String.format("(%s)", FunctionUtil.getFunctionWith(Global.program, t.getParent().getStart())));
            s.append(" => ");
        }
        return s.toString().substring(0, s.length() - 4); // Remove the last " => "
    }

    /**
     * Converts the path of addresses to a string representation.
     * 
     * @return A string representation of the address path.
     */
    public String printPath() {
        StringBuilder s = new StringBuilder();
        for (Address p : path) {
            s.append(String.format("%x", p.getUnsignedOffset()));
            s.append(String.format("(%s)", FunctionUtil.getFunctionWith(Global.program, p)));
            s.append(" => ");
        }
        return s.toString().substring(0, s.length() - 4); // Remove the last " => "
    }
}
