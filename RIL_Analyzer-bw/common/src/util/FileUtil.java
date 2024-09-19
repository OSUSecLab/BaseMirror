package util;

import analyze.Constants;
import ghidra.program.model.listing.Function;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * FileUtil provides utility methods for file operations including reading, writing, and searching files.
 */
public class FileUtil {

    /**
     * Writes the given content to a file at the specified path. If the append parameter is true,
     * content is appended to the file; otherwise, it overwrites the file.
     *
     * @param path The file path where content should be written.
     * @param content The content to write to the file.
     * @param append If true, append content to the file; otherwise, overwrite the file.
     */
    public static void writeToFile(String path, String content, boolean append) {
        try {
            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(path, append)));
            if (!append && content.equals("")) {
                out.print(content);
            } else {
                out.println(content);
            }
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Writes a list of objects to a file. Each object in the list is converted to a string
     * and written to a new line in the file. The append parameter controls whether to append
     * to the file or overwrite it.
     *
     * @param path The file path where the list should be written.
     * @param list The list of objects to write to the file.
     * @param append If true, append to the file; otherwise, overwrite the file.
     */
    public static void writeListToFile(String path, List<?> list, boolean append) {
        try {
            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(path, append)));
            for (Object item : list) {
                out.println(item.toString());
            }
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Checks if a file with a name containing the specified name exists in the output directory.
     *
     * @param name The name to search for in the output directory.
     * @return True if a file containing the specified name exists; otherwise, false.
     */
    public static boolean isResultExist(String name) {
        File file = new File(Constants.OUTPUT_DIR);
        String[] files = file.list();
        if (files == null)
            return false;

        for (String fname : files) {
            if (fname.contains(name))
                return true;
        }

        return false;
    }

    /**
     * Reads lines from a file and returns them as a list of strings. Each line in the file
     * is added to the list.
     *
     * @param fileName The name of the file to read.
     * @return A list of strings, each representing a line from the file.
     */
    public static List<String> readListFromFile(String fileName) {
        BufferedReader reader;
        List<String> results = new ArrayList<>();
        try {
            reader = new BufferedReader(new FileReader(fileName));
            String line = reader.readLine();
            while (line != null) {
                results.add(line.replace("\n", ""));
                line = reader.readLine();
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return results;
    }

    /**
     * Lists all files in the specified directory.
     *
     * @param dir The directory to list files from.
     * @return An array of files in the directory.
     */
    public static File[] listFilesForFolder(String dir) {
        File folder = new File(dir);
        return folder.listFiles();
    }

    /**
     * Checks if a file contains a specific string.
     *
     * @param file The file to search.
     * @param str The string to search for.
     * @return True if the file contains the specified string; otherwise, false.
     */
    public static boolean fileContainsString(File file, String str) {
        try {
            Scanner scanner = new Scanner(file);
            while (scanner.hasNextLine()) {
                if (scanner.nextLine().contains(str)) {
                    return true;
                }
            }
            scanner.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Searches for a line containing the specified library name in the file "./all_so.txt".
     *
     * @param libName The name of the library to search for.
     * @return The line containing the library name, or null if not found.
     */
    public static String searchPathInFile(String libName) {
        try {
            Scanner scanner = new Scanner(new File("./all_so.txt"));
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (line.contains(libName)) {
                    return line;
                }
            }
            scanner.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Searches for "libsec-ril.so" files in the directory specified by Constants.RIL_BINARIES
     * and adds their absolute paths to the provided list.
     *
     * @param rilsPath The list to which the paths of "libsec-ril.so" files will be added.
     */
    public static void getRilsPath(List<String> rilsPath) {
        Path path = Paths.get(Constants.RIL_BINARIES);
        if (Files.exists(path) && Files.isDirectory(path)) {
            try {
                Files.walk(path)
                .filter(Files::isRegularFile)
                .filter(p -> p.getFileName().toString().equals("libsec-ril.so"))
                .forEach(p -> rilsPath.add(p.toAbsolutePath().toString()));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
