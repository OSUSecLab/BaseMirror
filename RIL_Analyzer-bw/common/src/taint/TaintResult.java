package taint;

import com.google.gson.JsonObject;
import org.json.JSONObject;

import java.util.Map;

/**
 * Represents the result of a taint analysis.
 */
public class TaintResult {

    public Map<Integer, String> args; // Map of argument indices to their corresponding string representations
    public String func; // Name of the function where taint was detected
    public String refAddr; // Address where the taint was referenced
    public String taintFunc; // Name of the taint source function

    /**
     * Constructs a TaintResult with the specified taint function, function name,
     * reference address, and arguments.
     * 
     * @param taintFunc The name of the taint source function.
     * @param func The name of the function where taint was detected.
     * @param refAddr The address where the taint was referenced.
     * @param args A map of argument indices to their string representations.
     */
    public TaintResult(String taintFunc, String func, String refAddr, Map<Integer, String> args) {
        this.taintFunc = taintFunc;
        this.func = func;
        this.refAddr = refAddr;
        this.args = args;
    }

    /**
     * Returns a string representation of the TaintResult.
     * 
     * @return A formatted string describing the source function, reference function,
     *         and arguments.
     */
    @Override
    public String toString() {
        return String.format("Source: %s\tFunc: %s\tArgs: %s", taintFunc, func, args);
    }

    /**
     * Converts the TaintResult to a JSON object.
     * 
     * @return A JSONObject containing the taint function, reference function, reference
     *         address, and arguments.
     */
    public JSONObject toJsonObj() {
        JSONObject res = new JSONObject();
        res.put("BaseAPI", taintFunc);
        res.put("RefFunc", func);
        res.put("RefAddr", refAddr);
        res.put("Args", args);
        return res;
    }
}
