package taint;

import analyze.Global;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import util.FunctionUtil;
import util.RILLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a taint analysis path in the program.
 */
public class TaintPath {

    public Integer taintFd; // File descriptor associated with taint analysis
    public Function taintFdFunc; // Function associated with taint analysis
    public List<Integer> taintArgs; // Arguments related to taint analysis
    public List<PcodeOp> trace; // List of Pcode operations in the trace
    public Map<PcodeOp, Varnode> traceNode; // Mapping of Pcode operations to Varnodes
    public List<Address> path; // List of addresses in the taint path
    public Map<Integer, Long> taintResult; // Taint results as long values (e.g., from ioctl())
    public boolean falseNegative = false; // Flag indicating if there was a false negative
    public Map<Integer, List<Byte>> taintResultByteArray; // Taint results as byte arrays (e.g., from write())

    public List<Integer> forwardArgs; // Arguments for forward taint analysis
    public List<PcodeOp> forwardTrace; // List of Pcode operations in the forward trace
    public Map<PcodeOp, Varnode> forwardTraceNode; // Mapping of Pcode operations to Varnodes in the forward trace
    public List<Address> forwardPath; // List of addresses in the forward taint path
    public Map<Integer, Long> forwardResult; // Forward taint analysis results as long values
    public Map<Integer, List<Byte>> forwardResultByteArray; // Forward taint analysis results as byte arrays

    public TaintPath() {
        // Default constructor
    }

    /**
     * Constructs a TaintPath with initial values.
     *
     * @param fd The file descriptor associated with taint analysis.
     * @param func The function associated with taint analysis.
     * @param args The list of arguments related to taint analysis.
     */
    public TaintPath(Integer fd, Function func, List<Integer> args) {
        path = new ArrayList<>();
        trace = new ArrayList<>();
        traceNode = new HashMap<>();
        taintFd = fd;
        taintFdFunc = func;
        taintArgs = args;
        taintResult = new HashMap<>();
        taintResultByteArray = new HashMap<>();

        forwardArgs = new ArrayList<>();
        forwardArgs.add(-1);

        forwardTrace = new ArrayList<>();
        forwardPath = new ArrayList<>();
        forwardResult = new HashMap<>();
        forwardResultByteArray = new HashMap<>();
    }

    /**
     * Adds an address to the forward taint path.
     *
     * @param a The address to add.
     */
    public void addToForwardPath(Address a) {
        forwardPath.add(a);
    }

    /**
     * Adds a Pcode operation to the forward trace.
     *
     * @param p The Pcode operation to add.
     */
    public void addToForwardTrace(PcodeOp p) {
        forwardTrace.add(p);
    }

    /**
     * Gets the forward argument index at a specified position.
     *
     * @param i The index position.
     * @return The forward argument index.
     */
    public int getForwardArgIndex(int i) {
        return forwardArgs.get(i);
    }

    /**
     * Updates the forward argument at a specified index.
     *
     * @param idx The index position.
     * @param val The new value.
     */
    public void updateForwardArg(int idx, int val) {
        forwardArgs.set(idx, val);
    }

    /**
     * Adds an address to the taint path.
     *
     * @param a The address to add.
     */
    public void addToPath(Address a) {
        path.add(a);
    }

    /**
     * Adds a Pcode operation to the trace.
     *
     * @param p The Pcode operation to add.
     */
    public void addToTrace(PcodeOp p) {
        trace.add(p);
    }

    /**
     * Adds a Pcode operation and its associated Varnode to the trace node map.
     *
     * @param p The Pcode operation.
     * @param node The Varnode associated with the Pcode operation.
     */
    public void addToTraceNode(PcodeOp p, Varnode node) {
        String TAG = "[addToTraceNode] ";
        if (traceNode.containsKey(p)) {
            RILLog.debugLog(TAG + "conflict key");
        } else {
            traceNode.put(p, node);
        }
    }

    /**
     * Checks if the trace contains a specific Pcode operation.
     *
     * @param p The Pcode operation to check.
     * @return True if the trace contains the Pcode operation, false otherwise.
     */
    public boolean containsTrace(PcodeOp p) {
        for (PcodeOp op : trace) {
            if (p.toString().equals(op.toString())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the path contains a specific address.
     *
     * @param a The address to check.
     * @return True if the path contains the address, false otherwise.
     */
    public boolean containsPath(Address a) {
        for (Address addr : path) {
            if (addr.getUnsignedOffset() == a.getUnsignedOffset()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Adds a result to the taint result map.
     *
     * @param idx The index of the result.
     * @param val The long value of the result.
     */
    public void putResult(int idx, long val) {
        String TAG = "[TaintPath::putResult] ";
        if (taintResult.containsKey(idx)) {
            RILLog.debugLog(TAG + "complicated result with same idx");
            assert 0 > 1; // Trigger an assertion failure for debugging
        }
        taintResult.put(idx, val);
    }

    /**
     * Adds a result to the taint result map and stores the byte array representation.
     *
     * @param idx The index of the result.
     * @param array The byte array result.
     */
    public void putResult(int idx, List<Byte> array) {
        String TAG = "[TaintPath::putResult] ";
        if (taintResult.containsKey(idx)) {
            RILLog.debugLog(TAG + "duplicated result with same idx");
            assert 0 > 1; // Trigger an assertion failure for debugging
        }
        taintResult.put(idx, -1L);
        taintResultByteArray.put(idx, array);
    }

    /**
     * Checks if the path is empty.
     *
     * @return True if the path is empty, false otherwise.
     */
    public boolean pathEmpty() {
        return path.size() == 0;
    }

    /**
     * Updates the file descriptor associated with taint analysis.
     *
     * @param fd The new file descriptor.
     */
    public void updateFd(Integer fd) {
        taintFd = fd;
    }

    /**
     * Updates the function associated with the file descriptor.
     *
     * @param func The new function.
     */
    public void updateFdFunc(Function func) {
        taintFdFunc = func;
    }

    /**
     * Adds an argument index to the list of taint arguments.
     *
     * @param idx The argument index to add.
     */
    public void addArgIndex(int idx) {
        if (!taintArgs.contains(idx)) {
            taintArgs.add(idx);
        }
    }

    /**
     * Gets the argument index at a specified position.
     *
     * @param i The index position.
     * @return The argument index.
     */
    public int getArgIndex(int i) {
        return taintArgs.get(i);
    }

    /**
     * Removes an argument from the list by setting its value to -1.
     *
     * @param idx The index of the argument to remove.
     */
    public void removeArg(int idx) {
        updateArg(idx, -1);
    }

    /**
     * Updates the argument at a specified index.
     *
     * @param idx The index position.
     * @param val The new value.
     */
    public void updateArg(int idx, int val) {
        taintArgs.set(idx, val);
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
     * Gets the taint results as a map of indices to long values.
     *
     * @return The taint results map.
     */
    public Map<Integer, Long> getResult() {
        return taintResult;
    }

    /**
     * Gets the taint results as a map of indices to byte arrays.
     *
     * @return The taint results byte array map.
     */
    public Map<Integer, List<Byte>> getResultByteArray() {
        return taintResultByteArray;
    }

    /**
     * Checks if there are any results in the taint analysis.
     *
     * @return True if there are results, false otherwise.
     */
    public boolean hasResult() {
        return taintResult.size() != 0 || taintResultByteArray.size() != 0;
    }

    @Override
    public TaintPath clone() {
        TaintPath p = new TaintPath();
        p.taintFd = this.taintFd;
        p.taintFdFunc = this.taintFdFunc;
        p.taintArgs = new ArrayList<>(this.taintArgs);
        p.traceNode = new HashMap<>(this.traceNode);
        p.path = new ArrayList<>(this.path);
        p.trace = new ArrayList<>(this.trace);
        p.taintResult = new HashMap<>(this.taintResult);
        p.falseNegative = this.falseNegative;
        p.taintResultByteArray = new HashMap<>(this.taintResultByteArray);

        p.forwardArgs = new ArrayList<>(this.forwardArgs);

        p.forwardTrace = new ArrayList<>(this.forwardTrace);
        p.forwardPath = new ArrayList<>(this.forwardPath);
        p.forwardResult = new HashMap<>(this.forwardResult);
        p.forwardResultByteArray = new HashMap<>(this.forwardResultByteArray);

        return p;
    }

    /**
     * Prints the trace of Pcode operations in a readable format.
     *
     * @return The trace as a string.
     */
    public String printTrace() {
        StringBuilder s = new StringBuilder();
        for (PcodeOp t : trace) {
            s.append(String.format("%x", t.getParent().getStart().getUnsignedOffset()));
            s.append(String.format("(%s)", FunctionUtil.getFunctionWith(Global.program, t.getParent().getStart())));
            s.append(" => ");
        }
        return s.toString().substring(0, s.length() - 4); // remove the last ==>
    }

    /**
     * Prints the path of addresses in a readable format.
     *
     * @return The path as a string.
     */
    public String printPath() {
        StringBuilder s = new StringBuilder();
        for (Address p : path) {
            s.append(String.format("%x", p.getUnsignedOffset()));
            s.append(String.format("(%s)", FunctionUtil.getFunctionWith(Global.program, p)));
            s.append(" => ");
        }
        return s.toString().substring(0, s.length() - 4); // remove the last ==>
    }
}
