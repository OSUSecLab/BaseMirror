package util;

import aQute.bnd.service.diff.Tree;
import analyze.Config;
import analyze.Global;
import ghidra.program.model.pcode.*;

import java.util.ArrayList;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PCodeUtil provides utility methods for evaluating and manipulating PCode representations.
 */
public class PCodeUtil {

    /**
     * Evaluates the given Varnode into a string representation.
     *
     * @param node The Varnode to evaluate.
     * @return The string representation of the Varnode.
     */
    public static String evaluateVarNode(Varnode node) {
        if (node == null)
            return null;
        try {
            return evaluate(node, new StringBuilder(), 0).toString();
        } catch (StackOverflowError | OutOfMemoryError e) {
            return node.toString().trim();
        }
    }

    /**
     * Recursively evaluates a Varnode into a string representation.
     *
     * @param node The Varnode to evaluate.
     * @param expression The current expression being built.
     * @param depth The current depth of recursion.
     * @return The string representation of the Varnode.
     * @throws StackOverflowError If recursion exceeds depth limit.
     * @throws OutOfMemoryError If memory is exhausted during evaluation.
     */
    private static StringBuilder evaluate(Varnode node, StringBuilder expression, int depth) throws StackOverflowError, OutOfMemoryError {
        if (depth >= Config.MAX_PCODE_EVAL_DEPTH) {
            System.out.println("[ERROR] PCodeUtil.evaluate() reaches max dive: " + node.toString());
            return new StringBuilder(node.toString().trim());
        }

        PcodeOp defNode = node.getDef();

        if (defNode == null) {
            // Base case: no definition
            return new StringBuilder(node.toString().trim());
        }

        String mnem = defNode.getMnemonic();
        Varnode[] inputs = defNode.getInputs();

        switch (mnem) {
            case "CAST":
            case "COPY":
                // Ignore mnemonic and evaluate inputs
                for (Varnode input : inputs) {
                    StringBuilder newExp = evaluate(input, new StringBuilder(""), depth + 1);
                    expression.append(newExp);
                    expression.append(" ");
                }
                return new StringBuilder(expression.toString().trim());

            case "INDIRECT":
                // Evaluate the first input node
                return new StringBuilder(evaluate(inputs[0], new StringBuilder(), depth + 1));

            case "MULTIEQUAL":
                // Select a non-zero input and evaluate it
                Varnode zeroNode = null;
                for (Varnode input : inputs) {
                    if (!(input.isConstant() && input.getAddress().getUnsignedOffset() == 0)) {
                        return new StringBuilder(evaluate(input, new StringBuilder(), depth + 1));
                    } else {
                        zeroNode = input;
                    }
                }
                if (zeroNode != null)
                    return new StringBuilder(zeroNode.toString());
                else
                    return new StringBuilder();

            default:
                // Handle other mnemonics
                expression.append(defNode.getMnemonic());
                expression.append(" ");
                for (Varnode input : inputs) {
                    StringBuilder newExp = evaluate(input, new StringBuilder(""), depth + 1);
                    expression.append(newExp);
                    expression.append(" ");
                }
                return new StringBuilder(expression.toString().trim());
        }
    }

    /**
     * Evaluates a Varnode considering high-level function information and tainted parameters.
     *
     * @param node The Varnode to evaluate.
     * @param hf The HighFunction containing context for evaluation.
     * @param taintedParams A set of tainted parameter indices.
     * @return The string representation of the Varnode.
     */
    public static String evaluateVarNode(Varnode node, HighFunction hf, TreeSet<Integer> taintedParams) {
        if (node == null) {
            RILLog.debugLog("[evaluateVarNode] node is null");
            return null;
        }
        try {
            RILLog.debugLog("[evaluateVarNode] evaluating " + node.toString());
            return evaluate(node, hf, taintedParams, new StringBuilder()).toString();
        } catch (StackOverflowError | OutOfMemoryError e) {
            RILLog.debugLog("[evaluateVarNode] exception " + node.toString());
            return node.toString().trim();
        }
    }

    /**
     * Recursively evaluates a Varnode into a string representation with high-level function context.
     *
     * @param node The Varnode to evaluate.
     * @param hf The HighFunction containing context for evaluation.
     * @param taintedParams A set of tainted parameter indices.
     * @param expression The current expression being built.
     * @return The string representation of the Varnode.
     * @throws StackOverflowError If recursion exceeds depth limit.
     * @throws OutOfMemoryError If memory is exhausted during evaluation.
     */
    private static StringBuilder evaluate(Varnode node, HighFunction hf, TreeSet<Integer> taintedParams, StringBuilder expression) throws StackOverflowError, OutOfMemoryError {
        RILLog.debugLog("[evaluate] evaluate node: " + node.toString());
        PcodeOp defNode = node.getDef();
        RILLog.debugLog("[evaluate] try get def node");

        if (defNode == null) {
            // Base case: no definition
            RILLog.debugLog("[evaluate] def code is null");
            int paramIdx = markIfParam(node, hf, taintedParams);
            RILLog.debugLog("[evaluate] get paramIdx " + paramIdx);
            if (paramIdx == -1) {
                // Not a parameter
                return new StringBuilder(node.toString().trim());
            } else {
                // Is a parameter
                return new StringBuilder("xParam_" + paramIdx);
            }
        } else {
            RILLog.debugLog("[evaluate] get def code: " + defNode.toString());
            String mnem = defNode.getMnemonic();
            Varnode[] inputs = defNode.getInputs();
            RILLog.debugLog("[evaluate] Mnemonic: " + mnem);
            RILLog.debugLog("[evaluate] Inputs:");
            for (Varnode input : inputs) {
                RILLog.debugLog(input.toString());
            }

            switch (mnem) {
                case "CAST":
                case "COPY":
                    // Ignore mnemonic and evaluate inputs
                    for (Varnode input : inputs) {
                        StringBuilder newExp = evaluate(input, hf, taintedParams, new StringBuilder(""));
                        RILLog.debugLog("[evaluate] for input: " + input.toString() + " get exp: " + newExp);
                        expression.append(newExp);
                        expression.append(" ");
                    }
                    return new StringBuilder(expression.toString().trim());

                case "INDIRECT":
                    // Evaluate the first input node
                    return new StringBuilder(evaluate(inputs[0], hf, taintedParams, new StringBuilder()));

                case "MULTIEQUAL":
                    // Select a non-zero input and evaluate it
                    Varnode zeroNode = null;
                    for (Varnode input : inputs) {
                        if (!(input.isConstant() && input.getAddress().getUnsignedOffset() == 0)) {
                            return new StringBuilder(evaluate(input, hf, taintedParams, new StringBuilder()));
                        } else {
                            zeroNode = input;
                        }
                    }
                    if (zeroNode != null)
                        return new StringBuilder(zeroNode.toString());
                    else
                        return new StringBuilder();

                default:
                    // Handle other mnemonics
                    RILLog.debugLog("[evaluate] switch default");
                    expression.append(defNode.getMnemonic());
                    expression.append(" ");
                    for (Varnode input : inputs) {
                        StringBuilder newExp = evaluate(input, hf, taintedParams, new StringBuilder(""));
                        expression.append(newExp);
                        expression.append(" ");
                    }
                    return new StringBuilder(expression.toString().trim());
            }
        }
    }

    /**
     * Marks a Varnode as a parameter if it matches a parameter in the HighFunction.
     *
     * @param node The Varnode to check.
     * @param hf The HighFunction containing parameter information.
     * @param taintedParams A set to add indices of tainted parameters.
     * @return The index of the parameter if it matches; otherwise, -1.
     */
    private static int markIfParam(Varnode node, HighFunction hf, TreeSet<Integer> taintedParams) {
        LocalSymbolMap symbolMap = hf.getLocalSymbolMap();
        int num = symbolMap.getNumParams();
        for (int i = 0; i < num; i++) {
            String highParam = symbolMap.getParamSymbol(i).getHighVariable().getRepresentative().toString();
            if (node.toString().equals(highParam)) {
                taintedParams.add(i);
                return i;
            }
        }
        return -1;
    }

    /**
     * Removes specific "LOAD" expressions from the given function name.
     *
     * @param funcName The function name to modify.
     * @return The function name with "LOAD" expressions removed.
     */
    public static String removeLoadPcodeExp(String funcName) {
        funcName = funcName.replace("LOAD (const, 0x1b1, 4) ", "");
        funcName = funcName.replace("LOAD (const, 0x1a1, 4) ", "");
        // TODO: Handle additional LOAD expression formats if necessary
        return funcName;
    }

    /**
     * Converts integer addition to pointer addition format in the expression.
     *
     * @param exp The expression to convert.
     * @return The modified expression with "INT_ADD" replaced by "PTRADD".
     */
    public static String intAdd2ptrAdd(String exp) {
        exp = exp.replace("INT_ADD", "PTRADD");
        return String.format("%s (const, 0x1, %d)", exp, Global.POINTER_SIZE); // TODO: Temporary solution
    }

    /**
     * Gets the parameter index of a Varnode if it matches a parameter in the HighFunction.
     *
     * @param node The Varnode to check.
     * @return The index of the parameter if it matches; otherwise, -1.
     */
    public static int getNodeParamIndex(Varnode node) {
        HighFunction hf = node.getHigh().getHighFunction();
        int num = hf.getLocalSymbolMap().getNumParams();
        for (int i = 0; i < num; i++) {
            LocalSymbolMap localSymbolMap = hf.getLocalSymbolMap();
            if (localSymbolMap != null) {
                HighParam param = localSymbolMap.getParam(i);
                if (localSymbolMap.getParam(i) != null && node.equals(param.getRepresentative())) {
                    return i;
                }
            }
        }
        return -1;
    }
}
