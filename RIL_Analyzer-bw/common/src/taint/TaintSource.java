package taint;

import analyze.Global;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import util.FunctionUtil;

import java.util.LinkedList;
import java.util.List;

/**
 * Represents a taint source in the program, identified by a function name or address.
 */
public class TaintSource {

    String name; // Name of the function where taint originates
    Address address; // Entry point address of the function or specified address
    Integer fd_arg; // File descriptor argument associated with the taint source
    List<Integer> args; // List of arguments associated with the taint source

    /**
     * Constructs a TaintSource using the function name, file descriptor argument,
     * and a list of arguments.
     * 
     * @param funcName The name of the function where taint originates.
     * @param fd The file descriptor argument associated with the taint source.
     * @param argList A list of arguments associated with the taint source.
     */
    public TaintSource(String funcName, Integer fd, List<Integer> argList) {
        name = funcName;
        Function f = FunctionUtil.getFunctionWithName(Global.getProgram(), funcName);
        if (f != null)
            this.address = f.getEntryPoint(); // Set the address to the entry point of the function if found
        this.fd_arg = fd;
        this.args = new LinkedList<>(argList);
    }

    /**
     * Constructs a TaintSource using a specific address, file descriptor argument,
     * and a list of arguments.
     * 
     * @param address The address associated with the taint source.
     * @param fd The file descriptor argument associated with the taint source.
     * @param args A list of arguments associated with the taint source.
     */
    public TaintSource(Address address, Integer fd, List<Integer> args) {
        this.address = address;
        this.fd_arg = fd;
        this.args = args;
    }

    /**
     * Gets the address of the taint source.
     * 
     * @return The address of the taint source.
     */
    public Address getAddress() {
        return address;
    }

    /**
     * Gets the name of the function where taint originates.
     * 
     * @return The name of the function.
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the list of arguments associated with the taint source.
     * 
     * @return A list of arguments.
     */
    public List<Integer> getArgs() {
        return args;
    }
}
